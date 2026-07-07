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

// LocationMetric holds the per-instance location-distance row used by the
// patched best-path comparator (D-014). Each GoBGP instance mounts one
// perspective (source location) and looks up destination metrics from the
// path's stamped :40: large community.
var LocationMetric LocationMetricTable

type LocationMetricTable struct {
	GlobalAdmin           uint32
	PerspectiveLocationID uint32
	Destinations          map[uint32]uint32

	missingLookups atomic.Uint64
}

func (t *LocationMetricTable) Enabled() bool {
	return t.GlobalAdmin != 0 && t.PerspectiveLocationID != 0 && len(t.Destinations) > 0
}

func (t *LocationMetricTable) Reset() {
	t.GlobalAdmin = 0
	t.PerspectiveLocationID = 0
	t.Destinations = nil
	t.missingLookups.Store(0)
}

func (t *LocationMetricTable) MissingLookupCount() uint64 {
	return t.missingLookups.Load()
}

func (t *LocationMetricTable) MetricForPath(path *Path) uint32 {
	if !t.Enabled() {
		return 0
	}

	locID, ok := locationIDFromPath(path, t.GlobalAdmin)
	if !ok {
		t.missingLookups.Add(1)
		return LocationMetricMissingSentinel
	}

	if locID == t.PerspectiveLocationID {
		return 0
	}

	if metric, ok := t.Destinations[locID]; ok {
		return metric
	}

	t.missingLookups.Add(1)
	return LocationMetricMissingSentinel
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
	if !LocationMetric.Enabled() {
		return nil
	}

	m1 := LocationMetric.MetricForPath(path1)
	m2 := LocationMetric.MetricForPath(path2)
	if m1 == m2 {
		return nil
	}
	if m1 < m2 {
		return path1
	}
	return path2
}
