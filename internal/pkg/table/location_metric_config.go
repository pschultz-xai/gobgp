// Copyright (C) 2026 Bendrr contributors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package table

import (
	"fmt"
	"os"
	"sort"
	"sync/atomic"

	"gopkg.in/yaml.v3"
)

// locationMetricFile is the mounted per-instance map (D-014): one row of the
// global distance matrix, source = this GoBGP instance's location perspective.
//
//	version: 1
//	global_admin: 64500
//	perspective_location_id: 104
//	destinations:
//	  102: 50
//	  185: 120
type locationMetricFile struct {
	Version               int               `yaml:"version"`
	GlobalAdmin           uint32            `yaml:"global_admin"`
	PerspectiveLocationID uint32            `yaml:"perspective_location_id"`
	Destinations          map[uint32]uint32 `yaml:"destinations"`
}

// locationRegistryFile is the subset of the Community Name Registry (D-028)
// needed for startup validation: the :40: location dimension.
type locationRegistryFile struct {
	GlobalAdmin uint32            `yaml:"global_admin"`
	Location    map[uint32]string `yaml:"location"`
}

// locationMetricPaths remembers the mounted file paths from the startup load
// so an explicit reload (D-066) re-reads the same artifacts.
var locationMetricPaths atomic.Pointer[[2]string]

// LocationMetricPaths returns the (mapPath, registryPath) recorded by
// LoadLocationMetricFile, or ("", "") when no map was mounted at startup.
func LocationMetricPaths() (string, string) {
	p := locationMetricPaths.Load()
	if p == nil {
		return "", ""
	}
	return p[0], p[1]
}

// ParseLocationMetricFile parses and validates a location-metric map without
// installing it. registryPath is optional (""); when given, the map is
// cross-checked against the location registry so a missing or unknown
// location fails loudly instead of surfacing later as an unexplained ranking
// anomaly (D-014). Used by both the startup load (fail-fast) and the D-066
// reload (fail-safe: caller keeps the running table on error).
func ParseLocationMetricFile(mapPath, registryPath string) (*LocationMetricTable, error) {
	raw, err := os.ReadFile(mapPath)
	if err != nil {
		return nil, fmt.Errorf("location-metric: reading %s: %w", mapPath, err)
	}

	var f locationMetricFile
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("location-metric: parsing %s: %w", mapPath, err)
	}

	if f.GlobalAdmin == 0 {
		return nil, fmt.Errorf("location-metric: %s: global_admin is required and must be nonzero", mapPath)
	}
	if f.PerspectiveLocationID == 0 {
		return nil, fmt.Errorf("location-metric: %s: perspective_location_id is required and must be nonzero", mapPath)
	}
	if len(f.Destinations) == 0 {
		return nil, fmt.Errorf("location-metric: %s: destinations map is empty", mapPath)
	}
	for locID, metric := range f.Destinations {
		if metric >= LocationMetricMissingSentinel {
			return nil, fmt.Errorf("location-metric: %s: destination %d metric %d collides with reserved sentinel range (>= %d)",
				mapPath, locID, metric, LocationMetricMissingSentinel)
		}
	}

	if registryPath != "" {
		if err := validateAgainstRegistry(&f, registryPath); err != nil {
			return nil, err
		}
	}

	dests := make(map[uint32]uint32, len(f.Destinations))
	for k, v := range f.Destinations {
		dests[k] = v
	}
	// Own-location metric 0 is computed in MetricForPath, not stored; a
	// config-generation artifact that includes the perspective row is
	// harmless but must not override the 0 default.
	delete(dests, f.PerspectiveLocationID)

	return &LocationMetricTable{
		GlobalAdmin:           f.GlobalAdmin,
		PerspectiveLocationID: f.PerspectiveLocationID,
		Destinations:          dests,
	}, nil
}

// LoadLocationMetricFile parses, validates and installs the mounted
// location-metric map (startup path). Must be called before the BGP server
// starts serving; afterwards the table only changes via the D-066 reload,
// which swaps it atomically and recomputes best paths.
func LoadLocationMetricFile(mapPath, registryPath string) error {
	t, err := ParseLocationMetricFile(mapPath, registryPath)
	if err != nil {
		return err
	}
	InstallLocationMetric(t)
	locationMetricPaths.Store(&[2]string{mapPath, registryPath})
	return nil
}

func validateAgainstRegistry(f *locationMetricFile, registryPath string) error {
	raw, err := os.ReadFile(registryPath)
	if err != nil {
		return fmt.Errorf("location-metric: reading registry %s: %w", registryPath, err)
	}

	var reg locationRegistryFile
	if err := yaml.Unmarshal(raw, &reg); err != nil {
		return fmt.Errorf("location-metric: parsing registry %s: %w", registryPath, err)
	}
	if len(reg.Location) == 0 {
		return fmt.Errorf("location-metric: registry %s has no location entries", registryPath)
	}

	if reg.GlobalAdmin != 0 && reg.GlobalAdmin != f.GlobalAdmin {
		return fmt.Errorf("location-metric: global_admin mismatch: map has %d, registry has %d",
			f.GlobalAdmin, reg.GlobalAdmin)
	}

	if _, ok := reg.Location[f.PerspectiveLocationID]; !ok {
		return fmt.Errorf("location-metric: perspective_location_id %d not in location registry",
			f.PerspectiveLocationID)
	}

	var unknown, missing []uint32
	for locID := range f.Destinations {
		if _, ok := reg.Location[locID]; !ok {
			unknown = append(unknown, locID)
		}
	}
	for locID := range reg.Location {
		if locID == f.PerspectiveLocationID {
			continue
		}
		if _, ok := f.Destinations[locID]; !ok {
			missing = append(missing, locID)
		}
	}

	if len(unknown) > 0 {
		sort.Slice(unknown, func(i, j int) bool { return unknown[i] < unknown[j] })
		return fmt.Errorf("location-metric: destinations reference location ids not in registry: %v", unknown)
	}
	if len(missing) > 0 {
		sort.Slice(missing, func(i, j int) bool { return missing[i] < missing[j] })
		return fmt.Errorf("location-metric: registry locations missing from destinations map: %v (every location must have a metric row or startup fails, D-014)", missing)
	}
	return nil
}
