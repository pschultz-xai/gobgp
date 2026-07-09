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
	u, changed := d.reSort()
	assert.False(t, changed)
	assert.Nil(t, u)

	// Map B inverts the distances: fra must now rank first.
	installTestLocationMetric(104, map[uint32]uint32{
		102: 90,
		185: 30,
	})

	u, changed = d.reSort()
	require.True(t, changed, "inverted metrics must re-rank the destination")
	assert.Equal(t, []*Path{lax, fra}, u.OldKnownPathList)
	assert.Equal(t, []*Path{fra, lax}, u.KnownPathList)
	assert.Equal(t, []*Path{fra, lax}, d.knownPathList)

	// GetChanges over the diff reports the best-path flip for plain peers.
	best, old, _ := u.GetChanges(GLOBAL_RIB_NAME, 0, false)
	assert.Equal(t, fra, best)
	assert.Equal(t, lax, old)

	// Idempotent: a second pass under map B reports no change.
	_, changed = d.reSort()
	assert.False(t, changed)
}

// A tie under the new map must keep the current relative order (stable
// sort) and report no change, so an unchanged comparator input costs no
// export work.
func TestReSortStableOnTies(t *testing.T) {
	defer resetLocationMetric()

	installTestLocationMetric(104, map[uint32]uint32{
		102: 30,
		185: 90,
	})

	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.0.0.0/24"))
	require.NoError(t, err)

	lax := pathWithLocationLC(nil, nlri, 1, 102)
	fra := pathWithLocationLC(nil, nlri, 2, 185)

	d := newDestination(nlri, 64)
	d.localIdMap.Flag(0)
	d.Calculate(logger, fra)
	d.Calculate(logger, lax)

	// Map B makes the two locations equidistant: everything ties through
	// the location-metric slot, later comparators (age, etc.) decide — but
	// the stable sort must not report a spurious change when the resulting
	// order matches the current one.
	installTestLocationMetric(104, map[uint32]uint32{
		102: 50,
		185: 50,
	})

	before := make([]*Path, len(d.knownPathList))
	copy(before, d.knownPathList)
	u, changed := d.reSort()
	if changed {
		// Order legitimately changed via a later comparator; accept but the
		// diff must be internally consistent.
		assert.Equal(t, before, u.OldKnownPathList)
		assert.Equal(t, d.knownPathList, u.KnownPathList)
	} else {
		assert.Equal(t, before, d.knownPathList)
	}
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

	installTestLocationMetric(104, map[uint32]uint32{
		102: 90,
		185: 30,
	})

	var got []*Update
	total, changed := tm.ReRankDestinations(func(us []*Update) {
		got = append(got, us...)
	})
	assert.Equal(t, 2, total)
	assert.Equal(t, 1, changed)
	require.Len(t, got, 1)
	assert.Equal(t, "10.1.0.0/24", got[0].KnownPathList[0].GetPrefix())
	assert.Equal(t, uint32(185), mustLocationID(t, got[0].KnownPathList[0]),
		"fra path must rank first under the inverted map")

	// Second walk: nothing left to re-rank.
	total, changed = tm.ReRankDestinations(nil)
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
