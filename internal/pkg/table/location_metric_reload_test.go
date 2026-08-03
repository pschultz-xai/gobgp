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
	"net/netip"
	"testing"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// D-066: swapping the location-metric map invalidates the sorted invariant
// of every knownPathList; reSort must restore it and report a diff usable
// for export propagation.
func TestReSortAfterLocationMetricSwap(t *testing.T) {
	defer resetLocationMetric()

	installTestLocationMetric(104, map[uint32]uint32{
		102: 30, // lax — closer under map A
		185: 90, // fra — farther under map A
	})

	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.0.0.0/24"))
	require.NoError(t, err)

	lax := pathWithLocationLC(nil, nlri, 1, 102)
	fra := pathWithLocationLC(nil, nlri, 2, 185)

	d := newDestination(nlri, 64)
	d.localIdMap.Flag(0)
	d.Calculate(logger, fra)
	d.Calculate(logger, lax)
	require.Equal(t, []*Path{lax, fra}, d.knownPathList, "map A must rank lax first")

	// Same map content: reSort is a no-op and reports no change.
	u, changed := d.reSort(CurrentLocationMetric())
	assert.False(t, changed)
	assert.Nil(t, u)

	// Map B inverts the distances: fra must now rank first.
	oldTbl := CurrentLocationMetric()
	installTestLocationMetric(104, map[uint32]uint32{
		102: 90,
		185: 30,
	})

	u, changed = d.reSort(oldTbl)
	require.True(t, changed, "inverted metrics must re-rank the destination")
	assert.Equal(t, []*Path{lax, fra}, u.OldKnownPathList)
	assert.Equal(t, []*Path{fra, lax}, u.KnownPathList)
	assert.Equal(t, []*Path{fra, lax}, d.knownPathList)

	// GetChanges over the diff reports the best-path flip for plain peers.
	best, old, _ := u.GetChanges(GLOBAL_RIB_NAME, 0, false)
	assert.Equal(t, fra, best)
	assert.Equal(t, lax, old)

	// Idempotent: a second pass under map B reports no change.
	_, changed = d.reSort(CurrentLocationMetric())
	assert.False(t, changed)
}

// R-037 pin: a reload that changes bucket membership WITHOUT moving the
// ranked order must still report the destination changed, or the export
// selection never re-runs and a peer keeps a stale bucket cut. Both
// directions: a tie merging (bucket widens — a path must be announced) and
// a tie splitting (bucket narrows — a path must be withdrawn).
func TestReSortReportsBucketPartitionChange(t *testing.T) {
	defer resetLocationMetric()

	installTestLocationMetric(104, map[uint32]uint32{
		102: 30,
		185: 90,
	})

	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.0.0.0/24"))
	require.NoError(t, err)

	// Distinct iBGP sources with ordered router IDs so the full-tie
	// tie-break (router ID) is deterministic and prefers lax: source-less
	// local paths tie all the way down to the asymmetric
	// compareByNeighborAddress fallback, which does not order two
	// invalid-address paths consistently.
	laxSrc := &PeerInfo{AS: 65000, LocalAS: 65000,
		ID: netip.MustParseAddr("1.1.1.1"), Address: netip.MustParseAddr("10.0.0.1")}
	fraSrc := &PeerInfo{AS: 65000, LocalAS: 65000,
		ID: netip.MustParseAddr("2.2.2.2"), Address: netip.MustParseAddr("10.0.0.2")}
	lax := pathWithLocationLC(laxSrc, nlri, 1, 102)
	fra := pathWithLocationLC(fraSrc, nlri, 2, 185)

	d := newDestination(nlri, 64)
	d.localIdMap.Flag(0)
	d.Calculate(logger, lax)
	d.Calculate(logger, fra)
	require.Equal(t, []*Path{lax, fra}, d.knownPathList)

	// Tie merge: 30/90 -> 50/50. The order stays lax-first (metric under
	// map A, router ID under map B), but fra joins lax's bucket and must
	// be re-exported.
	oldTbl := CurrentLocationMetric()
	installTestLocationMetric(104, map[uint32]uint32{
		102: 50,
		185: 50,
	})
	u, changed := d.reSort(oldTbl)
	require.True(t, changed, "tie merge must report a change despite stable order")
	assert.Equal(t, []*Path{lax, fra}, u.OldKnownPathList)
	assert.Equal(t, []*Path{lax, fra}, u.KnownPathList, "order must not move")
	assert.True(t, EqualThroughLocationMetric(lax, fra))

	// Tie split: 50/50 -> 50/80. Order holds (lax still first), but fra
	// leaves the bucket and must be withdrawn from bucket-mode peers.
	oldTbl = CurrentLocationMetric()
	installTestLocationMetric(104, map[uint32]uint32{
		102: 50,
		185: 80,
	})
	u, changed = d.reSort(oldTbl)
	require.True(t, changed, "tie split must report a change despite stable order")
	assert.Equal(t, []*Path{lax, fra}, u.KnownPathList, "order must not move")
	assert.False(t, EqualThroughLocationMetric(lax, fra))

	// Metric values move but the partition and order both hold
	// (50/80 -> 55/85): nothing to re-export, no change reported.
	oldTbl = CurrentLocationMetric()
	installTestLocationMetric(104, map[uint32]uint32{
		102: 55,
		185: 85,
	})
	_, changed = d.reSort(oldTbl)
	assert.False(t, changed, "value drift preserving the partition must not re-export")
}

// D-066: the TableManager walk must visit every destination, re-sort only
// the affected ones, and hand shard batches to the callback.
func TestReRankDestinationsWalk(t *testing.T) {
	defer resetLocationMetric()

	installTestLocationMetric(104, map[uint32]uint32{
		102: 30,
		185: 90,
	})

	tm := NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC})

	// Destination 1: two paths whose order flips with the map.
	nlri1, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.1.0.0/24"))
	require.NoError(t, err)
	tm.Update(pathWithLocationLC(nil, nlri1, 1, 102))
	tm.Update(pathWithLocationLC(nil, nlri1, 2, 185))

	// Destination 2: a single path — can never re-rank.
	nlri2, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.2.0.0/24"))
	require.NoError(t, err)
	tm.Update(pathWithLocationLC(nil, nlri2, 1, 102))

	oldTbl := CurrentLocationMetric()
	installTestLocationMetric(104, map[uint32]uint32{
		102: 90,
		185: 30,
	})

	var got []*Update
	total, changed := tm.ReRankDestinations(oldTbl, func(us []*Update) {
		got = append(got, us...)
	})
	assert.Equal(t, 2, total)
	assert.Equal(t, 1, changed)
	require.Len(t, got, 1)
	assert.Equal(t, "10.1.0.0/24", got[0].KnownPathList[0].GetPrefix())
	assert.Equal(t, uint32(185), mustLocationID(t, got[0].KnownPathList[0]),
		"fra path must rank first under the inverted map")

	// Second walk: nothing left to re-rank.
	total, changed = tm.ReRankDestinations(CurrentLocationMetric(), nil)
	assert.Equal(t, 2, total)
	assert.Equal(t, 0, changed)
}

// ParseLocationMetricFile must validate without touching the installed table.
func TestParseLocationMetricFileDoesNotInstall(t *testing.T) {
	defer resetLocationMetric()

	running := installTestLocationMetric(104, map[uint32]uint32{102: 30})

	mapPath := writeTempYAML(t, "metric.yaml", `
global_admin: 64500
perspective_location_id: 105
destinations:
  102: 10
`)
	parsed, err := ParseLocationMetricFile(mapPath, "")
	require.NoError(t, err)
	assert.Equal(t, uint32(105), parsed.PerspectiveLocationID)
	assert.Same(t, running, CurrentLocationMetric(), "parse must not install")
	assert.False(t, parsed.Equal(running))
	assert.True(t, parsed.Equal(&LocationMetricTable{
		GlobalAdmin:           64500,
		PerspectiveLocationID: 105,
		Destinations:          map[uint32]uint32{102: 10},
	}))
}

func mustLocationID(t *testing.T, p *Path) uint32 {
	t.Helper()
	for _, lc := range p.GetLargeCommunities() {
		if lc.ASN == testGlobalAdmin && lc.LocalData1 == LocationLCDimension {
			return lc.LocalData2
		}
	}
	t.Fatalf("path %v has no location LC", p)
	return 0
}
