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

package server

// R-037 export selector unit tests: pure admit/exhausted semantics over
// ranked candidates, with the D-014 location-metric table mounted so bucket
// equivalence is real (not the disabled-comparator degenerate case).

import (
	"net/netip"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// selTestPath builds an injected-style candidate stamped with a :40:
// location LC, mirroring what the PSA injects (identical attributes except
// the location LC and path id).
func selTestPath(t *testing.T, pathID uint32, locationID uint32) *table.Path {
	t.Helper()
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.99.0.0/24"))
	require.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeLargeCommunities([]*bgp.LargeCommunity{
			{ASN: lmTestGlobalAdmin, LocalData1: table.LocationLCDimension, LocalData2: locationID},
		}),
	}
	return table.NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri, ID: pathID}, false, attrs, time.Now(), false)
}

func admitAll(sel *exportSelector, paths []*table.Path) []bool {
	out := make([]bool, len(paths))
	for i, p := range paths {
		out[i] = sel.admit(p)
	}
	return out
}

func TestExportSelectorFlatModeMatchesSendMax(t *testing.T) {
	mountLocationMetricTable(t, map[uint32]uint32{10: 5, 20: 10})

	// bucketMax 0 = flat: first sendMax survivors, regardless of metric.
	sel := newExportSelector(exportSelection{sendMax: 2})
	paths := []*table.Path{
		selTestPath(t, 1, 10),
		selTestPath(t, 2, 20),
		selTestPath(t, 3, 10),
	}
	assert.Equal(t, []bool{true, true, false}, admitAll(&sel, paths))
	assert.True(t, sel.exhausted())
}

func TestExportSelectorFlatModeUncapped(t *testing.T) {
	mountLocationMetricTable(t, map[uint32]uint32{10: 5})

	// sendMax 0 must mean "no cap", never "export nothing".
	sel := newExportSelector(exportSelection{})
	paths := []*table.Path{
		selTestPath(t, 1, 10),
		selTestPath(t, 2, 10),
	}
	assert.Equal(t, []bool{true, true}, admitAll(&sel, paths))
	assert.False(t, sel.exhausted())
}

func TestExportSelectorBestBucketOnly(t *testing.T) {
	// The motivating case: 2 paths at metric 100, 2 at metric 200, all
	// other attributes identical, room for all four under sendMax — only
	// the best bucket is exported.
	mountLocationMetricTable(t, map[uint32]uint32{10: 100, 20: 100, 30: 200, 40: 200})

	sel := newExportSelector(exportSelection{sendMax: 4, bucketMax: 4, minPaths: 2})
	paths := []*table.Path{
		selTestPath(t, 1, 10),
		selTestPath(t, 2, 20),
		selTestPath(t, 3, 30),
		selTestPath(t, 4, 40),
	}
	assert.Equal(t, []bool{true, true, false, false}, admitAll(&sel, paths))
	assert.False(t, sel.exhausted(),
		"bucket slots remain, so a later tying candidate could still be admitted")
}

func TestExportSelectorBucketCap(t *testing.T) {
	// More bucket members than lowest-igp-max: cap inside the bucket.
	mountLocationMetricTable(t, map[uint32]uint32{10: 100, 20: 100, 30: 100})

	sel := newExportSelector(exportSelection{sendMax: 4, bucketMax: 2, minPaths: 2})
	paths := []*table.Path{
		selTestPath(t, 1, 10),
		selTestPath(t, 2, 20),
		selTestPath(t, 3, 30),
	}
	assert.Equal(t, []bool{true, true, false}, admitAll(&sel, paths))
	assert.True(t, sel.exhausted())
}

func TestExportSelectorFloorFill(t *testing.T) {
	// Thin bucket (1 member), minPaths 2: the next-ranked non-bucket path
	// fills the floor; further non-bucket paths are rejected.
	mountLocationMetricTable(t, map[uint32]uint32{10: 100, 30: 200, 40: 300})

	sel := newExportSelector(exportSelection{sendMax: 4, bucketMax: 4, minPaths: 2})
	paths := []*table.Path{
		selTestPath(t, 1, 10),
		selTestPath(t, 2, 30),
		selTestPath(t, 3, 40),
	}
	assert.Equal(t, []bool{true, true, false}, admitAll(&sel, paths))
	assert.False(t, sel.exhausted(),
		"bucket slots remain — a later tying candidate (non-contiguous MED case) could still be admitted")
}

func TestExportSelectorNonContiguousBucketMember(t *testing.T) {
	// compareByMED comparability can interleave a non-bucket path between
	// bucket members in ranked order; a later tying path must still get a
	// bucket slot.
	mountLocationMetricTable(t, map[uint32]uint32{10: 100, 20: 100, 30: 200})

	sel := newExportSelector(exportSelection{sendMax: 4, bucketMax: 4, minPaths: 2})
	paths := []*table.Path{
		selTestPath(t, 1, 10), // anchor
		selTestPath(t, 2, 30), // filler (floor 2)
		selTestPath(t, 3, 20), // ties with anchor — bucket member
	}
	assert.Equal(t, []bool{true, true, true}, admitAll(&sel, paths))
}

func TestExportSelectorSendMaxCeiling(t *testing.T) {
	// sendMax below bucketMax: the ceiling wins.
	mountLocationMetricTable(t, map[uint32]uint32{10: 100, 20: 100, 30: 100})

	sel := newExportSelector(exportSelection{sendMax: 2, bucketMax: 8, minPaths: 2})
	paths := []*table.Path{
		selTestPath(t, 1, 10),
		selTestPath(t, 2, 20),
		selTestPath(t, 3, 30),
	}
	assert.Equal(t, []bool{true, true, false}, admitAll(&sel, paths))
	assert.True(t, sel.exhausted())
}

func TestExportSelectorNoMetricTableOneBucket(t *testing.T) {
	// Without a mounted metric map the comparator is disabled: identical
	// candidates form one bucket and selection degrades to
	// min(fan, bucketMax) — the compatibility property the rig relies on
	// until it mounts a matrix.
	table.ResetLocationMetric()
	t.Cleanup(table.ResetLocationMetric)

	sel := newExportSelector(exportSelection{sendMax: 8, bucketMax: 4, minPaths: 2})
	paths := []*table.Path{
		selTestPath(t, 1, 10),
		selTestPath(t, 2, 20),
		selTestPath(t, 3, 30),
		selTestPath(t, 4, 40),
		selTestPath(t, 5, 50),
	}
	assert.Equal(t, []bool{true, true, true, true, false}, admitAll(&sel, paths))
}

func TestExportSelectorSelectionActive(t *testing.T) {
	assert.False(t, exportSelection{}.active())
	assert.True(t, exportSelection{sendMax: 4}.active())
	assert.True(t, exportSelection{bucketMax: 4}.active())
}
