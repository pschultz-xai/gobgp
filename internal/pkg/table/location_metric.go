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
	"maps"
	"sync/atomic"
)

const (
	// LocationLCDimension is the large-community LocalData1 value for the
	// stamped location classification dimension (D-011 :40:).
	LocationLCDimension uint32 = 40

	// LocationMetricMissingSentinel is returned when a path's location LC is
	// absent from the mounted map. Deliberately max-1, not literal max (D-014).
	LocationMetricMissingSentinel uint32 = ^uint32(0) - 1
)

// locationMetric holds the currently installed per-instance location-distance
// row used by the patched best-path comparator (D-014). It is an atomic
// pointer so an explicit config reload (D-066) can swap the whole table while
// best-path selection is running; each comparison loads the pointer once, so
// a comparison is internally consistent even mid-swap. Installed tables are
// immutable: reload builds a fresh LocationMetricTable and swaps it in.
var locationMetric atomic.Pointer[LocationMetricTable]

type LocationMetricTable struct {
	GlobalAdmin           uint32
	PerspectiveLocationID uint32
	Destinations          map[uint32]uint32

	missingLookups atomic.Uint64
}

// CurrentLocationMetric returns the installed table, or nil when no map is
// mounted. The returned table must be treated as read-only.
func CurrentLocationMetric() *LocationMetricTable {
	return locationMetric.Load()
}

// InstallLocationMetric atomically swaps the installed table. Passing nil
// disables the comparator. The caller is responsible for triggering the
// full best-path recomputation that a swap on a live server requires (D-066).
func InstallLocationMetric(t *LocationMetricTable) {
	locationMetric.Store(t)
}

// ResetLocationMetric removes the installed table (test helper).
func ResetLocationMetric() {
	locationMetric.Store(nil)
}

func (t *LocationMetricTable) Enabled() bool {
	return t != nil && t.GlobalAdmin != 0 && t.PerspectiveLocationID != 0 && len(t.Destinations) > 0
}

func (t *LocationMetricTable) MissingLookupCount() uint64 {
	if t == nil {
		return 0
	}
	return t.missingLookups.Load()
}

// Equal reports whether two tables rank identically (counter excluded).
func (t *LocationMetricTable) Equal(o *LocationMetricTable) bool {
	if t == nil || o == nil {
		return t == o
	}
	return t.GlobalAdmin == o.GlobalAdmin &&
		t.PerspectiveLocationID == o.PerspectiveLocationID &&
		maps.Equal(t.Destinations, o.Destinations)
}

// MetricForPath returns the path's metric and counts missing lookups —
// the D-014 alerting signal for RIB content the map cannot rank. Use it on
// the ranking path (compareByLocationMetric) only; bookkeeping reads that
// scale with export volume or reload walks must use MetricForPathQuiet so
// the counter keeps meaning "paths in the RIB the map doesn't know".
func (t *LocationMetricTable) MetricForPath(path *Path) uint32 {
	m, missing := t.metricForPath(path)
	if missing {
		t.missingLookups.Add(1)
	}
	return m
}

// MetricForPathQuiet is MetricForPath without the missing-lookup counter
// bump (bucket-equivalence checks, reload partition bookkeeping).
func (t *LocationMetricTable) MetricForPathQuiet(path *Path) uint32 {
	m, _ := t.metricForPath(path)
	return m
}

func (t *LocationMetricTable) metricForPath(path *Path) (metric uint32, missing bool) {
	if !t.Enabled() {
		return 0, false
	}

	locID, ok := locationIDFromPath(path, t.GlobalAdmin)
	if !ok {
		return LocationMetricMissingSentinel, true
	}

	if locID == t.PerspectiveLocationID {
		return 0, false
	}

	if metric, ok := t.Destinations[locID]; ok {
		return metric, false
	}

	return LocationMetricMissingSentinel, true
}

func locationIDFromPath(path *Path, globalAdmin uint32) (uint32, bool) {
	for _, lc := range path.GetLargeCommunities() {
		if lc.ASN == globalAdmin && lc.LocalData1 == LocationLCDimension {
			return lc.LocalData2, true
		}
	}
	return 0, false
}

func compareByLocationMetric(path1, path2 *Path) *Path {
	t := locationMetric.Load()
	if !t.Enabled() {
		return nil
	}

	m1 := t.MetricForPath(path1)
	m2 := t.MetricForPath(path2)
	if m1 == m2 {
		return nil
	}
	if m1 < m2 {
		return path1
	}
	return path2
}
