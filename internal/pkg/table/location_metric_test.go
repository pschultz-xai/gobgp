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
	"time"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testGlobalAdmin uint32 = 64500

func TestLocationMetricTable_prefersLowerMetric(t *testing.T) {
	defer resetLocationMetric()

	tbl := installTestLocationMetric(104 /* ord */, map[uint32]uint32{
		102: 50,  // lax
		185: 120, // fra
	})

	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.0.0.0/24"))
	require.NoError(t, err)

	lax := pathWithLocationLC(nil, nlri, 1, 102)
	fra := pathWithLocationLC(nil, nlri, 2, 185)

	assert.Equal(t, lax, compareByLocationMetric(lax, fra))
	assert.Equal(t, uint64(0), tbl.MissingLookupCount())
}

func TestLocationMetricTable_sameMetricReturnsNil(t *testing.T) {
	defer resetLocationMetric()

	installTestLocationMetric(104, map[uint32]uint32{
		102: 50,
		185: 50,
	})

	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.0.0.0/24"))
	require.NoError(t, err)

	p1 := pathWithLocationLC(nil, nlri, 1, 102)
	p2 := pathWithLocationLC(nil, nlri, 2, 185)

	assert.Nil(t, compareByLocationMetric(p1, p2))
}

func TestLocationMetricTable_ownLocationDefaultsToZero(t *testing.T) {
	defer resetLocationMetric()

	installTestLocationMetric(104, map[uint32]uint32{
		102: 50,
	})

	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.0.0.0/24"))
	require.NoError(t, err)

	own := pathWithLocationLC(nil, nlri, 1, 104)
	remote := pathWithLocationLC(nil, nlri, 2, 102)

	assert.Equal(t, own, compareByLocationMetric(own, remote))
}

func TestLocationMetricTable_missingLocationUsesSentinelAndAlerts(t *testing.T) {
	defer resetLocationMetric()

	tbl := installTestLocationMetric(104, map[uint32]uint32{
		102: 50,
	})

	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.0.0.0/24"))
	require.NoError(t, err)

	known := pathWithLocationLC(nil, nlri, 1, 102)
	missingLC := pathWithoutLocationLC(nil, nlri)
	unknownLoc := pathWithLocationLC(nil, nlri, 2, 999)

	assert.Equal(t, uint32(LocationMetricMissingSentinel), tbl.MetricForPath(missingLC))
	assert.Equal(t, uint32(LocationMetricMissingSentinel), tbl.MetricForPath(unknownLoc))
	assert.Equal(t, known, compareByLocationMetric(known, missingLC))
	assert.Equal(t, known, compareByLocationMetric(known, unknownLoc))
	assert.Equal(t, uint64(4), tbl.MissingLookupCount())
}

// Spike 1 gate 1a (D-042): injected (API/local) paths rank above iBGP-learned paths.
func TestMixedRIBSemantics_injectedRemoteBeatsIBGPLocal(t *testing.T) {
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.0.0.0/24"))
	require.NoError(t, err)

	ibgpLocal := pathWithLocationLC(newIBGPPeer("10.0.0.1"), nlri, 0, 104)
	require.True(t, ibgpLocal.IsIBGP(), "test peer must be genuinely iBGP")
	require.False(t, ibgpLocal.IsLocal())

	injectedRemote := pathWithLocationLC(nil, nlri, 1, 185)
	require.True(t, injectedRemote.IsLocal(), "API-injected path must be locally sourced")

	assert.Equal(t, injectedRemote, compareByLocalOrigin(injectedRemote, ibgpLocal))
	assert.Equal(t, injectedRemote, compareByLocalOrigin(ibgpLocal, injectedRemote))
}

// Spike 1 gate 1a (D-042): remote-vs-remote ordering uses location metric after
// compareByLocalOrigin is a no-op among injected paths.
func TestMixedRIBSemantics_remoteVsRemoteUsesLocationMetric(t *testing.T) {
	defer resetLocationMetric()

	installTestLocationMetric(104, map[uint32]uint32{
		102: 30,
		185: 90,
	})

	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.0.0.0/24"))
	require.NoError(t, err)

	lax := pathWithLocationLC(nil, nlri, 1, 102)
	fra := pathWithLocationLC(nil, nlri, 2, 185)

	assert.Nil(t, compareByLocalOrigin(lax, fra))
	assert.Equal(t, lax, compareByLocationMetric(lax, fra))
}

// Spike 1 gate 1a (D-042) — the full-chain semantics pin. Runs the real
// destination Calculate/insertSort path (not isolated comparator functions) so
// that a GoBGP rebase which moves or changes compareByLocalOrigin, or displaces
// the D-014 location-metric slot, fails this test loudly.
//
// Expected knownPathList order (best first):
//  1. injected remote, lower location metric  (compareByLocalOrigin beats iBGP;
//     location metric orders remote-vs-remote)
//  2. injected remote, higher location metric
//  3. iBGP-learned local path (mesh-redundant; fills leftover SendMax slots)
func TestMixedRIBSemantics_fullChainOrdering(t *testing.T) {
	defer resetLocationMetric()

	installTestLocationMetric(104 /* ord perspective */, map[uint32]uint32{
		102: 30, // lax — closer
		185: 90, // fra — farther
	})

	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.0.0.0/24"))
	require.NoError(t, err)

	// Distinct path IDs mirror D-017: the PSA allocates a unique local path_id
	// per injected candidate, so same-source paths don't implicitly withdraw
	// each other.
	ibgpLocal := pathWithLocationLC(newIBGPPeer("10.0.0.1"), nlri, 0, 104)
	injectedFar := pathWithLocationLC(nil, nlri, 1, 185)
	injectedNear := pathWithLocationLC(nil, nlri, 2, 102)

	d := newDestination(nlri, 0)
	// Insert best-first to prove ordering comes from comparison, not arrival.
	d.Calculate(logger, injectedNear)
	d.Calculate(logger, injectedFar)
	d.Calculate(logger, ibgpLocal)

	require.Len(t, d.knownPathList, 3)
	assert.Equal(t, injectedNear, d.knownPathList[0], "nearest injected remote must rank first")
	assert.Equal(t, injectedFar, d.knownPathList[1], "farther injected remote must rank second")
	assert.Equal(t, ibgpLocal, d.knownPathList[2], "iBGP local path must rank last (D-042 remote-first)")

	// Same paths, reversed arrival order — ranking must be identical.
	d2 := newDestination(nlri, 0)
	d2.Calculate(logger, ibgpLocal)
	d2.Calculate(logger, injectedFar)
	d2.Calculate(logger, injectedNear)

	require.Len(t, d2.knownPathList, 3)
	assert.Equal(t, injectedNear, d2.knownPathList[0])
	assert.Equal(t, injectedFar, d2.knownPathList[1])
	assert.Equal(t, ibgpLocal, d2.knownPathList[2])
}

// Spike 1 contract §3.4 (LLGR): the LLGR_STALE well-known community is the
// FIRST slot in the best-path chain — above LOCAL_PREF, local-origin, and
// the D-014 location metric. A stale-but-nearest path (even an injected
// local-origin one) must rank below any fresh path, so LLGR depreference
// dominates Bendrr's ranked SendMax curation.
func TestSessionBehavior_llgrStaleRanksBelowEverything(t *testing.T) {
	defer resetLocationMetric()

	installTestLocationMetric(104, map[uint32]uint32{
		102: 30, // lax — closer
		185: 90, // fra — farther
	})

	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.0.0.0/24"))
	require.NoError(t, err)

	// Injected (local-origin) path, best location metric — but LLGR-stale.
	staleNear := pathWithLocationLC(nil, nlri, 1, 102)
	staleNear.SetCommunities([]uint32{uint32(bgp.COMMUNITY_LLGR_STALE)}, false)
	require.True(t, staleNear.IsLLGRStale())

	// Fresh iBGP-learned path, worst location metric — still must win.
	freshFar := pathWithLocationLC(newIBGPPeer("10.0.0.1"), nlri, 0, 185)

	d := newDestination(nlri, 0)
	d.Calculate(logger, staleNear)
	d.Calculate(logger, freshFar)

	require.Len(t, d.knownPathList, 2)
	assert.Equal(t, freshFar, d.knownPathList[0],
		"a fresh path must outrank an LLGR-stale path regardless of origin and metric")
	assert.Equal(t, staleNear, d.knownPathList[1])
}

func resetLocationMetric() {
	ResetLocationMetric()
}

// installTestLocationMetric installs a fresh table and returns it for
// counter/lookup assertions.
func installTestLocationMetric(perspective uint32, dests map[uint32]uint32) *LocationMetricTable {
	tbl := &LocationMetricTable{
		GlobalAdmin:           testGlobalAdmin,
		PerspectiveLocationID: perspective,
		Destinations:          dests,
	}
	InstallLocationMetric(tbl)
	return tbl
}

func newIBGPPeer(addr string) *PeerInfo {
	return &PeerInfo{
		AS:      65000,
		LocalAS: 65000, // AS == LocalAS makes IsIBGP() true
		Address: netip.MustParseAddr(addr),
	}
}

func pathWithLocationLC(source *PeerInfo, nlri *bgp.IPAddrPrefix, pathID uint32, locationID uint32) *Path {
	lc := bgp.NewPathAttributeLargeCommunities([]*bgp.LargeCommunity{
		{ASN: testGlobalAdmin, LocalData1: LocationLCDimension, LocalData2: locationID},
	})
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
			bgp.NewAs4PathParam(2, []uint32{65001}),
		}),
		lc,
	}
	return NewPath(bgp.RF_IPv4_UC, source, bgp.PathNLRI{NLRI: nlri, ID: pathID}, false, attrs, time.Now(), false)
}

func pathWithoutLocationLC(source *PeerInfo, nlri *bgp.IPAddrPrefix) *Path {
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
			bgp.NewAs4PathParam(2, []uint32{65001}),
		}),
	}
	return NewPath(bgp.RF_IPv4_UC, source, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
}
