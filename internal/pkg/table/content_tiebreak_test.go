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

// Bendrr R-278: the content-based final tie-break in rankBetterPath.
// These tests pin the three load-bearing claims of compareByContent:
//
//  1. It is a valid strict ordering (antisymmetric, transitive, never
//     first-argument-wins) — the property R-037 round-2 established for
//     the comparator chain and that insertSort/reSort trust.
//  2. It is a pure function of route content: localID, remoteID, source,
//     timestamps, and attribute slice order do not influence it, so
//     byte-identical content still ties and content-identical twins are
//     interchangeable.
//  3. Same path multiset, ANY arrival order, same final knownPathList
//     content order — the cross-pod determinism claim — and re-adding a
//     tied candidate no longer moves the winner (the churn class).

import (
	"bytes"
	"math/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tiedContentTime is a fixed timestamp shared by all paths in these tests
// so compareByAge ties deterministically and the chain falls through to
// the content comparator.
var tiedContentTime = time.Unix(100, 0)

// tiedContentPath builds a source-less (locally injected) path that ties
// with its siblings on every comparator above the content tie-break:
// identical ORIGIN/AS_PATH/NEXT_HOP, no MED, no LOCAL_PREF, same fixed
// timestamp. Content is distinguished only by the COMMUNITIES value, which
// no earlier comparator reads. pathID keeps the paths distinct for
// implicit-withdraw identity (D-017) without entering the content key.
func tiedContentPath(t *testing.T, pathID uint32, community uint32) *Path {
	t.Helper()
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.99.0.0/24"))
	require.NoError(t, err)
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.1"))
	require.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
			bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65001}),
		}),
		nh,
		bgp.NewPathAttributeCommunities([]uint32{community}),
	}
	return NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri, ID: pathID}, false, attrs, tiedContentTime, false)
}

// Antisymmetry and direction pin: a content-distinct fully-tied pair ranks
// identically regardless of argument order, and the LOWER content wins
// (the documented lowest-wins convention shared with the router-ID and
// neighbor-address steps).
func TestContentTieBreak_DistinctContentRanksSameBothArgumentOrders(t *testing.T) {
	low := tiedContentPath(t, 1, 100)
	high := tiedContentPath(t, 2, 200)

	assert.Equal(t, low, compareByContent(low, high))
	assert.Equal(t, low, compareByContent(high, low),
		"winner must not depend on argument order")
	assert.Equal(t, low, rankBetterPath(low, high))
	assert.Equal(t, low, rankBetterPath(high, low))
}

// Byte-identical content ties at the CONTENT step in both argument orders,
// no matter how the pod-local localID differs — and the chain then falls to
// compareByPathID (round-2 MAJOR-1), so rankBetterPath orders the twins by
// path id, lower first, in both argument orders. A full-chain nil requires
// identical content AND identical path id.
func TestContentTieBreak_IdenticalContentTiesThenPathIDOrders(t *testing.T) {
	p1 := tiedContentPath(t, 1, 100)
	p2 := tiedContentPath(t, 2, 100)
	p1.localID = 9 // higher localID on the lower-remoteID path: must not leak
	p2.localID = 3

	assert.Nil(t, compareByContent(p1, p2))
	assert.Nil(t, compareByContent(p2, p1))
	assert.Equal(t, p1, rankBetterPath(p1, p2),
		"content-identical twins must order by path id, lower first")
	assert.Equal(t, p1, rankBetterPath(p2, p1))

	// Same content AND same path id: genuine complete tie.
	p3 := tiedContentPath(t, 1, 100)
	assert.Nil(t, rankBetterPath(p1, p3))
	assert.Nil(t, rankBetterPath(p3, p1))
}

// Round-2 MAJOR-1 counterexample, reproduced as a pin: byte-identical
// twins differing only in ADD-PATH path id must rank identically across
// permuted arrival orders, and a re-add must not move the head. Before the
// compareByPathID step they were a complete tie, so insertSort placed by
// arrival ([3 2 1] vs [1 2 3] for opposite arrivals; re-add of id=1 moved
// the head) — exactly the nondeterminism R-278 exists to remove, visible
// through bucket-capped ADD-PATH export where receivers demux on path id.
func TestContentTieBreak_IdenticalTwinsArrivalAndReAddStable(t *testing.T) {
	twins := []*Path{
		tiedContentPath(t, 1, 100),
		tiedContentPath(t, 2, 100),
		tiedContentPath(t, 3, 100),
	}

	var reference []*Path
	permute(twins, func(perm []*Path) {
		d := newDestination(perm[0].GetNlri(), 0)
		for _, p := range perm {
			d.Calculate(logger, p)
		}
		require.Len(t, d.knownPathList, 3)
		if reference == nil {
			reference = append([]*Path(nil), d.knownPathList...)
			for i, p := range reference {
				assert.Equal(t, uint32(i+1), p.remoteID,
					"twins must rank by path id, lowest first")
			}
			return
		}
		assert.Equal(t, reference, d.knownPathList,
			"identical twins: same multiset, different arrival, different order")
	})

	// Re-add of the head twin (id=1): the head must not move.
	d := newDestination(twins[0].GetNlri(), 0)
	for _, p := range []int{2, 0, 1} { // arbitrary arrival
		d.Calculate(logger, twins[p])
	}
	reAdd := tiedContentPath(t, 1, 100)
	d.Calculate(logger, reAdd)
	require.Len(t, d.knownPathList, 3)
	assert.Same(t, reAdd, d.knownPathList[0],
		"re-added id=1 twin must occupy the id-1 rank slot")
	assert.Equal(t, uint32(2), d.knownPathList[1].remoteID)
	assert.Equal(t, uint32(3), d.knownPathList[2].remoteID)
}

// Attribute slice order is not content: the same attribute multiset stored
// in a different order (API-injected vs wire-learned construction can
// differ) must compare as identical. Pins the canonical-sort decision.
func TestContentTieBreak_AttrSliceOrderIsNotContent(t *testing.T) {
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.99.0.0/24"))
	require.NoError(t, err)
	origin := bgp.NewPathAttributeOrigin(0)
	aspath := bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
		bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65001}),
	})
	comms := bgp.NewPathAttributeCommunities([]uint32{100})

	p1 := NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri, ID: 1}, false,
		[]bgp.PathAttributeInterface{origin, aspath, comms}, tiedContentTime, false)
	p2 := NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri, ID: 2}, false,
		[]bgp.PathAttributeInterface{comms, origin, aspath}, tiedContentTime, false)

	assert.Nil(t, compareByContent(p1, p2),
		"same attribute multiset in a different slice order must tie")
	assert.Nil(t, compareByContent(p2, p1))
}

// MP_REACH nexthops ARE content and must order a pair that differs in
// nothing else. (The MP_REACH ID-twins prong below passes with or without
// the attr-walk exclusion under today's default Serialize, which omits
// per-NLRI IDs — the exclusion itself is pinned structurally by
// TestContentTieBreak_MpReachExcludedFromKeyStructurally.)
func TestContentTieBreak_MpReachNexthopCompared(t *testing.T) {
	v6nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:db8::/64"))
	require.NoError(t, err)

	v6Path := func(pathID, mpID uint32, nexthop string) *Path {
		mpreach, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC,
			[]bgp.PathNLRI{{NLRI: v6nlri, ID: mpID}}, netip.MustParseAddr(nexthop))
		require.NoError(t, err)
		attrs := []bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(0),
			bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
				bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65001}),
			}),
			mpreach,
		}
		return NewPath(bgp.RF_IPv6_UC, nil, bgp.PathNLRI{NLRI: v6nlri, ID: pathID}, false, attrs, tiedContentTime, false)
	}

	// Same content, different ADD-PATH identifiers inside MP_REACH and on
	// the path: a genuine tie.
	p1 := v6Path(1, 5, "2001:db8::1")
	p2 := v6Path(2, 9, "2001:db8::1")
	p1.localID = 5
	p2.localID = 9
	assert.Nil(t, compareByContent(p1, p2))
	assert.Nil(t, compareByContent(p2, p1))

	// Different MP_REACH nexthop is a content difference and must order
	// the pair consistently (lower nexthop first).
	pLow := v6Path(3, 5, "2001:db8::1")
	pHigh := v6Path(4, 5, "2001:db8::2")
	assert.Equal(t, pLow, compareByContent(pLow, pHigh))
	assert.Equal(t, pLow, compareByContent(pHigh, pLow))

	// Different MP_REACH link-local nexthop, everything else identical
	// (round-2 MAJOR-5.2): also content, also ordered consistently.
	llLow := v6Path(5, 5, "2001:db8::1")
	llHigh := v6Path(6, 5, "2001:db8::1")
	llLow.getPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI).(*bgp.PathAttributeMpReachNLRI).LinkLocalNexthop = netip.MustParseAddr("fe80::1")
	llHigh.getPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI).(*bgp.PathAttributeMpReachNLRI).LinkLocalNexthop = netip.MustParseAddr("fe80::2")
	assert.Equal(t, llLow, compareByContent(llLow, llHigh))
	assert.Equal(t, llLow, compareByContent(llHigh, llLow))
}

// Structural pin for the MP_REACH_NLRI exclusion (round-2 MAJOR-5.1): the
// behavioral ID-twins test above cannot kill an exclusion-removal mutant
// because default Serialize omits per-NLRI IDs today — so pin the
// invariant directly: a path carrying MP_REACH contributes NO attr entry
// of that type to its content key.
func TestContentTieBreak_MpReachExcludedFromKeyStructurally(t *testing.T) {
	v6nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:db8::/64"))
	require.NoError(t, err)
	mpreach, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC,
		[]bgp.PathNLRI{{NLRI: v6nlri, ID: 7}}, netip.MustParseAddr("2001:db8::1"))
	require.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		mpreach,
	}
	p := NewPath(bgp.RF_IPv6_UC, nil, bgp.PathNLRI{NLRI: v6nlri, ID: 1}, false, attrs, tiedContentTime, false)
	require.NotNil(t, p.getPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI))

	entries := contentAttrKeyEntries(p)
	require.Len(t, entries, 1, "only ORIGIN may contribute an entry")
	for _, e := range entries {
		require.NotEmpty(t, e)
		assert.NotEqual(t, byte(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI), e[0],
			"MP_REACH_NLRI must never contribute a content-key attr entry")
	}
}

// Attribute presence is content (round-2 MAJOR-5.3): a pair differing only
// by ATOMIC_AGGREGATE presence must order consistently in both argument
// orders. Direction pin, from the key layout: ATOMIC_AGGREGATE (type 6)
// sorts between NEXT_HOP (3) and COMMUNITIES (8), and its 2-byte entry's
// length prefix compares below the communities entry's at that position —
// so the path WITH the extra attribute compares lower here (presence is
// content, not "more attrs ranks later").
func TestContentTieBreak_AttrPresenceIsContent(t *testing.T) {
	without := tiedContentPath(t, 1, 100)
	with := tiedContentPath(t, 2, 100)
	with.setPathAttr(bgp.NewPathAttributeAtomicAggregate())

	winner := compareByContent(without, with)
	require.NotNil(t, winner,
		"presence-only attribute difference must not tie")
	assert.Equal(t, winner, compareByContent(with, without),
		"presence difference must order consistently in both argument orders")
	assert.Equal(t, with, winner)
}

// Wire-encoding artifacts are NOT content (round-2 MAJOR-4): the
// EXTENDED_LENGTH bit is a header-width choice and the PARTIAL bit a
// propagation artifact; gobgp retains whichever encoding the sender used
// (validatePathAttributeFlags masks both before checking) and Serialize
// reproduces it. Twins differing only in those flags must tie.
func TestContentTieBreak_WireEncodingArtifactsNormalized(t *testing.T) {
	base := tiedContentPath(t, 1, 100)

	extLen := tiedContentPath(t, 2, 100)
	origin := extLen.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN).(*bgp.PathAttributeOrigin)
	origin.Flags |= bgp.BGP_ATTR_FLAG_EXTENDED_LENGTH
	assert.Nil(t, compareByContent(base, extLen),
		"EXTENDED_LENGTH encoding must not be content")
	assert.Nil(t, compareByContent(extLen, base))

	partial := tiedContentPath(t, 3, 100)
	comms := partial.getPathAttr(bgp.BGP_ATTR_TYPE_COMMUNITIES).(*bgp.PathAttributeCommunities)
	comms.Flags |= bgp.BGP_ATTR_FLAG_PARTIAL
	assert.Nil(t, compareByContent(base, partial),
		"PARTIAL propagation artifact must not be content")
	assert.Nil(t, compareByContent(partial, base))
}

// The memoized content key must be invalidated by every attr mutation
// funnel (setPathAttr/delPathAttr — round-2 MAJOR-2's cache): rank once to
// warm the cache, mutate, and the comparison must reflect the new content.
func TestContentTieBreak_KeyInvalidatedOnAttrMutation(t *testing.T) {
	a := tiedContentPath(t, 1, 100)
	b := tiedContentPath(t, 2, 200)
	require.Equal(t, a, compareByContent(a, b), "warm both caches")

	// setPathAttr leg: raise a's communities value past b's.
	a.SetCommunities([]uint32{300}, true)
	assert.Equal(t, b, compareByContent(a, b),
		"attr mutation via setPathAttr must invalidate the cached key")
	assert.Equal(t, b, compareByContent(b, a))

	// delPathAttr leg: dropping the attribute changes the key again (the
	// smaller entry set compares as a byte-prefix, i.e. lower).
	a.delPathAttr(bgp.BGP_ATTR_TYPE_COMMUNITIES)
	assert.Equal(t, a, compareByContent(a, b),
		"attr deletion via delPathAttr must invalidate the cached key")
	assert.Equal(t, a, compareByContent(b, a))
}

// Round-3 MINOR-2: a clone reads attrs through the parent chain, so a
// content key copied onto the clone would go stale when the PARENT is later
// mutated through a funnel (the parent invalidates only its own cache).
// Clone therefore does NOT copy the key — this test pins the reviewer's
// scenario: warm the parent's key, clone, mutate the parent, and the
// clone's lazily recomputed key must match the parent's fresh one.
// SCOPE (round-3 verification): this closes the pre-first-computation
// window only. A clone whose key was already computed (i.e. the clone was
// ranked) still goes stale if the parent is mutated afterwards — no
// production sequence clones, ranks, then mutates the parent, so the
// residual is latent; do not treat clone keys as unconditionally coherent.
func TestContentTieBreak_CloneKeyBeforeFirstComputeNotStaleAfterParentMutation(t *testing.T) {
	parent := tiedContentPath(t, 1, 100)
	other := tiedContentPath(t, 2, 100)
	require.Nil(t, compareByContent(parent, other), "warm the parent's key")

	clone := parent.Clone(false)
	parent.SetCommunities([]uint32{300}, true)

	assert.Nil(t, compareByContent(clone, parent),
		"clone sees the parent's mutated attrs; a copied key would be stale")
	assert.Equal(t, parent.contentKeyBytes(), clone.contentKeyBytes())
	assert.NotNil(t, compareByContent(clone, other),
		"clone's content diverged from the unmutated twin")
}

// Round-3 MINOR-4: the per-entry length prefixes in the key are
// load-bearing framing. Reviewer's wire-reachable collision: COMMUNITIES
// [0x0a0b0c0d, 0x09801234] vs COMMUNITIES [0x0a0b0c0d] plus an unknown
// OPTIONAL attr type 0x09 with value 0x1234 — the unprefixed entry
// concatenations are byte-identical (08c00a0b0c0d09801234 both), so
// without framing the two attribute SETS would collide into one key.
func TestContentTieBreak_EntryFramingPreventsCollision(t *testing.T) {
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.99.0.0/24"))
	require.NoError(t, err)
	mk := func(pathID uint32, extra ...bgp.PathAttributeInterface) *Path {
		attrs := append([]bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(0),
		}, extra...)
		return NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri, ID: pathID}, false, attrs, tiedContentTime, false)
	}
	pA := mk(1, bgp.NewPathAttributeCommunities([]uint32{0x0a0b0c0d, 0x09801234}))
	pB := mk(2,
		bgp.NewPathAttributeCommunities([]uint32{0x0a0b0c0d}),
		bgp.NewPathAttributeUnknown(bgp.BGP_ATTR_FLAG_OPTIONAL, bgp.BGPAttrType(0x09), []byte{0x12, 0x34}),
	)

	// Collision precondition: the UNPREFIXED concatenations are identical.
	// If attr encodings ever change and this stops holding, the test has
	// gone vacuous and needs a new collision pair.
	require.Equal(t,
		bytes.Join(contentAttrKeyEntries(pA), nil),
		bytes.Join(contentAttrKeyEntries(pB), nil),
		"collision precondition lost — rebuild the pair")

	winner := compareByContent(pA, pB)
	require.NotNil(t, winner,
		"different attribute sets must not collide into one key")
	assert.Equal(t, winner, compareByContent(pB, pA))
}

// Round-3 MINOR-4 (second mutant) + NIT-1 behavioral pin: the tag byte in
// appendAddrKey is load-bearing — a plain IPv4 nexthop and its IPv4-mapped
// IPv6 form have IDENTICAL As16 expansions and are distinguished only by
// the tag. The pair is constructible from valid inputs: for an IPv6-family
// MP_REACH the constructor accepts a plain v4 nexthop (serialized as
// v4-mapped on the wire). The two in-memory forms are deliberately
// distinct content (see appendAddrKey), so they must order, not tie.
func TestContentTieBreak_NexthopTagByteDisambiguates(t *testing.T) {
	v6nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:db8:1::/64"))
	require.NoError(t, err)
	mk := func(pathID uint32, nexthop string) *Path {
		mpreach, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC,
			[]bgp.PathNLRI{{NLRI: v6nlri, ID: 5}}, netip.MustParseAddr(nexthop))
		require.NoError(t, err)
		attrs := []bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(0),
			mpreach,
		}
		return NewPath(bgp.RF_IPv6_UC, nil, bgp.PathNLRI{NLRI: v6nlri, ID: pathID}, false, attrs, tiedContentTime, false)
	}
	v4form := mk(1, "10.0.0.1")
	mapped := mk(2, "::ffff:10.0.0.1")

	nh1, _ := v4form.mpReachNexthops()
	nh2, _ := mapped.mpReachNexthops()
	require.Equal(t, nh1.As16(), nh2.As16(), "precondition: identical As16")
	require.NotEqual(t, nh1, nh2, "precondition: distinct netip forms")

	winner := compareByContent(v4form, mapped)
	require.NotNil(t, winner,
		"v4 and v4-mapped nexthop forms are distinct content (tag byte)")
	assert.Equal(t, winner, compareByContent(mapped, v4form))
}

// Round-3 MINOR-3: the key is retained for the life of the path, so its
// allocation must be exact — no permanently wasted capacity tail — and the
// documented 49-byte figure for the IPv4-unicast benchmark shape must hold.
func TestContentTieBreak_KeyAllocationExact(t *testing.T) {
	p := tiedContentPath(t, 1, 100)
	key := computePathContentKey(p)
	assert.Equal(t, cap(key), len(key), "retained key must have no spare capacity")
	assert.Len(t, key, 49, "documented key size for the IPv4-unicast benchmark shape")

	v6nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:db8::/64"))
	require.NoError(t, err)
	mpreach, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC,
		[]bgp.PathNLRI{{NLRI: v6nlri, ID: 5}}, netip.MustParseAddr("2001:db8::1"))
	require.NoError(t, err)
	mpreach.LinkLocalNexthop = netip.MustParseAddr("fe80::1")
	v6 := NewPath(bgp.RF_IPv6_UC, nil, bgp.PathNLRI{NLRI: v6nlri, ID: 1}, false,
		[]bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), mpreach}, tiedContentTime, false)
	v6key := computePathContentKey(v6)
	assert.Equal(t, cap(v6key), len(v6key), "exact for both-nexthops shape too")
}

// Default chain (ECRI off), differing timestamps: compareByAge sits ABOVE
// the content tie-break and still decides for non-iBGP pairs — the older
// path wins even when its content would lose (round-2 MINOR-4; every other
// test here pins same-second ties by construction).
func TestContentTieBreak_DefaultChainAgeOrdersAboveContent(t *testing.T) {
	require.False(t, SelectionOptions.ExternalCompareRouterId,
		"test requires the default ECRI-off chain")

	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.99.0.0/24"))
	require.NoError(t, err)
	mk := func(pathID, community uint32, ts time.Time) *Path {
		attrs := []bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(0),
			bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
				bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65001}),
			}),
			bgp.NewPathAttributeCommunities([]uint32{community}),
		}
		return NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri, ID: pathID}, false, attrs, ts, false)
	}

	// The OLDER path has the HIGHER content (would lose at the bottom).
	older := mk(1, 200, time.Unix(100, 0))
	newer := mk(2, 100, time.Unix(3700, 0))
	require.Equal(t, newer, compareByContent(older, newer), "content would prefer newer")

	assert.Equal(t, older, rankBetterPath(older, newer),
		"with defaults, age (oldest wins) must decide above content")
	assert.Equal(t, older, rankBetterPath(newer, older))
}

// Non-route-key NLRI payload (the MUP TEID that Path.Equal's serialized
// comparison exists for) is content: same route key, different TEID must
// order consistently.
func TestContentTieBreak_NonKeyNlriPayloadIsContent(t *testing.T) {
	pLow := mupT1stPath(t, netip.MustParseAddr("0.0.0.100"), netip.MustParseAddr("10.0.0.1"))
	pHigh := mupT1stPath(t, netip.MustParseAddr("0.0.0.200"), netip.MustParseAddr("10.0.0.1"))

	assert.Equal(t, pLow, compareByContent(pLow, pHigh))
	assert.Equal(t, pLow, compareByContent(pHigh, pLow))
}

// The R-277/R-278 motivating configuration: external-compare-router-id
// armed removes the age tie-break for the (non-iBGP) injected pair, so
// content must decide even when timestamps differ — arrival time no longer
// orders source-less pairs.
func TestContentTieBreak_ECRIArmedContentBeatsArrivalTime(t *testing.T) {
	oldECRI := SelectionOptions.ExternalCompareRouterId
	defer func() { SelectionOptions.ExternalCompareRouterId = oldECRI }()
	SelectionOptions.ExternalCompareRouterId = true

	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.99.0.0/24"))
	require.NoError(t, err)
	mk := func(pathID, community uint32, ts time.Time) *Path {
		attrs := []bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(0),
			bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
				bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65001}),
			}),
			bgp.NewPathAttributeCommunities([]uint32{community}),
		}
		return NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri, ID: pathID}, false, attrs, ts, false)
	}

	// The higher-content path is an hour OLDER — under the default chain
	// (ECRI off) age would prefer it; with ECRI armed, content decides.
	older := mk(1, 200, time.Unix(100, 0))
	newer := mk(2, 100, time.Unix(3700, 0))

	assert.Equal(t, newer, rankBetterPath(older, newer),
		"with ECRI armed, lower content must win regardless of age")
	assert.Equal(t, newer, rankBetterPath(newer, older))
}

// Ordering-validity property check plus the cross-pod determinism claim:
// over a set of content-distinct fully-tied paths, comparePathContent is
// antisymmetric and transitive, every distinct pair is strictly ordered,
// and the SAME path multiset delivered in ANY arrival order — via
// insertSort (destination Calculate) or via a full reSort of an unsorted
// list — produces the SAME final knownPathList order.
func TestContentTieBreak_OrderingValidityAndArrivalIndependence(t *testing.T) {
	const n = 6
	paths := make([]*Path, n)
	for i := range paths {
		paths[i] = tiedContentPath(t, uint32(i+1), uint32((i+1)*10))
	}

	// Antisymmetry + strictness over all pairs.
	for i := range paths {
		for j := range paths {
			c1 := comparePathContent(paths[i], paths[j])
			c2 := comparePathContent(paths[j], paths[i])
			if i == j {
				assert.Zero(t, c1)
				continue
			}
			assert.NotZero(t, c1, "distinct content must order strictly (%d,%d)", i, j)
			assert.Equal(t, c1 < 0, c2 > 0, "antisymmetry violated (%d,%d)", i, j)
		}
	}

	// Transitivity over all triples.
	for i := range paths {
		for j := range paths {
			for k := range paths {
				if comparePathContent(paths[i], paths[j]) <= 0 &&
					comparePathContent(paths[j], paths[k]) <= 0 {
					assert.LessOrEqual(t, comparePathContent(paths[i], paths[k]), 0,
						"transitivity violated (%d,%d,%d)", i, j, k)
				}
			}
		}
	}

	// insertSort determinism: every permutation of arrival order yields
	// the same knownPathList content order.
	var reference []*Path
	permute(paths, func(perm []*Path) {
		nlri := perm[0].GetNlri()
		d := newDestination(nlri, 0)
		for _, p := range perm {
			d.Calculate(logger, p)
		}
		require.Len(t, d.knownPathList, n)
		if reference == nil {
			reference = append([]*Path(nil), d.knownPathList...)
			// The reference itself must be strictly descending under the
			// comparator (sorted-invariant sanity).
			for i := 0; i+1 < len(reference); i++ {
				assert.Equal(t, reference[i], rankBetterPath(reference[i], reference[i+1]))
			}
			return
		}
		assert.Equal(t, reference, d.knownPathList,
			"same multiset, different arrival order, different final order")
	})

	// reSort agreement: a full stable re-sort of an arbitrarily ordered
	// list agrees with the insertSort-built order.
	for trial := range 20 {
		shuffled := append([]*Path(nil), paths...)
		rand.New(rand.NewSource(int64(trial))).Shuffle(n, func(i, j int) {
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		})
		d := newDestination(paths[0].GetNlri(), 0, shuffled...)
		d.reSort(nil, false)
		assert.Equal(t, reference, d.knownPathList,
			"reSort order must agree with insertSort order (trial %d)", trial)
	}
}

// permute calls fn with every permutation of s (Heap's algorithm; s is
// reused between calls, fn must not retain it).
func permute(s []*Path, fn func([]*Path)) {
	var rec func(k int)
	rec = func(k int) {
		if k == 1 {
			fn(s)
			return
		}
		for i := range k {
			rec(k - 1)
			if k%2 == 0 {
				s[i], s[k-1] = s[k-1], s[i]
			} else {
				s[0], s[k-1] = s[k-1], s[0]
			}
		}
	}
	rec(len(s))
}

// Churn regression: re-adding a tied candidate (implicitWithdraw +
// insertSort round trip through Calculate) must not move the winner.
// Pre-R-278 the complete tie made every re-add insert before its equal
// element, so the loser of the content order would jump to the front.
func TestContentTieBreak_ReAddDoesNotMoveWinner(t *testing.T) {
	winner := tiedContentPath(t, 1, 100)
	loser := tiedContentPath(t, 2, 200)

	d := newDestination(winner.GetNlri(), 0)
	d.Calculate(logger, winner)
	d.Calculate(logger, loser)
	require.Len(t, d.knownPathList, 2)
	require.Same(t, winner, d.knownPathList[0])

	// Re-add the loser: same source and path_id (implicit-withdraw
	// identity), same content, fresh Path object.
	loserReAdd := tiedContentPath(t, 2, 200)
	d.Calculate(logger, loserReAdd)
	require.Len(t, d.knownPathList, 2)
	assert.Same(t, winner, d.knownPathList[0],
		"re-adding a tied loser must not displace the winner")
	assert.Same(t, loserReAdd, d.knownPathList[1])

	// Re-add the winner: order equally unchanged.
	winnerReAdd := tiedContentPath(t, 1, 100)
	d.Calculate(logger, winnerReAdd)
	require.Len(t, d.knownPathList, 2)
	assert.Same(t, winnerReAdd, d.knownPathList[0])
	assert.Same(t, loserReAdd, d.knownPathList[1])
}

// Placement pin: the content tie-break lives BELOW the location-metric
// slot in rankBetterPath only. A content-distinct pair that ties through
// the metric slot must be ranked by content yet remain bucket-equal under
// EqualThroughLocationMetric — R-037 ADD-PATH bucket membership is
// unchanged by R-278.
func TestContentTieBreak_BucketMembershipUnchanged(t *testing.T) {
	defer resetLocationMetric()
	installTestLocationMetric(104, map[uint32]uint32{
		102: 50,
		185: 50, // same metric: ties through the metric slot
	})

	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.0.0.0/24"))
	require.NoError(t, err)
	lax := pathWithLocationLC(nil, nlri, 1, 102)
	fra := pathWithLocationLC(nil, nlri, 2, 185)

	winner := rankBetterPath(lax, fra)
	require.NotNil(t, winner, "content-distinct tied pair must be ranked")
	assert.Equal(t, winner, rankBetterPath(fra, lax))

	assert.True(t, EqualThroughLocationMetric(lax, fra),
		"content tie-break must not enter bucket equivalence")
}
