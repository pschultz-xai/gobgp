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

// Tests and benchmark for the R-256 withdraw-leg attribute-rewrite skip in
// UpdatePathAttrs.

import (
	"testing"
	"time"

	"net/netip"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func withdrawSkipGlobal() *oc.Global {
	return &oc.Global{Config: oc.GlobalConfig{As: 65000, RouterId: netip.MustParseAddr("10.0.0.254")}}
}

// withdrawSkipIBGPRRPeer builds the peer shape whose announce-leg rewrite is
// the richest: iBGP route-reflector client (ORIGINATOR_ID + CLUSTER_LIST +
// default LOCAL_PREF are all built).
func withdrawSkipIBGPRRPeer() *PeerInfo {
	return &PeerInfo{
		AS:                      65000,
		LocalAS:                 65000,
		Address:                 netip.MustParseAddr("10.0.0.2"),
		LocalAddress:            netip.MustParseAddr("10.0.0.254"),
		ID:                      netip.MustParseAddr("10.0.0.2"),
		LocalID:                 netip.MustParseAddr("10.0.0.254"),
		PeerType:                oc.PEER_TYPE_INTERNAL,
		RouteReflectorClient:    true,
		RouteReflectorClusterID: netip.MustParseAddr("10.0.0.100"),
	}
}

func withdrawSkipEBGPPeer() *PeerInfo {
	return &PeerInfo{
		AS:           65002,
		LocalAS:      65000,
		Address:      netip.MustParseAddr("10.0.0.3"),
		LocalAddress: netip.MustParseAddr("10.0.0.254"),
		ID:           netip.MustParseAddr("10.0.0.3"),
		LocalID:      netip.MustParseAddr("10.0.0.254"),
		PeerType:     oc.PEER_TYPE_EXTERNAL,
	}
}

// withdrawSkipAttrs approximates the bendrr injected-path attribute shape:
// origin, as-path, nexthop, MED, communities — deliberately WITHOUT
// LOCAL_PREF, so the pre-R-256 iBGP rewrite would visibly add one.
func withdrawSkipAttrs(t testing.TB) []bgp.PathAttributeInterface {
	t.Helper()
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.9"))
	require.NoError(t, err)
	return []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{65010, 65020})}),
		nh,
		bgp.NewPathAttributeMultiExitDisc(10),
		bgp.NewPathAttributeCommunities([]uint32{65010<<16 | 1, 65010<<16 | 2}),
	}
}

func withdrawSkipSource() *PeerInfo {
	src := netip.MustParseAddr("10.0.0.1")
	return &PeerInfo{
		AS: 65010, LocalAS: 65000,
		Address: src, ID: src,
		LocalID: netip.MustParseAddr("10.0.0.254"),
	}
}

func withdrawSkipV4Path(t testing.TB, isWithdraw bool) *Path {
	t.Helper()
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.99.0.0/24"))
	require.NoError(t, err)
	return NewPath(bgp.RF_IPv4_UC, withdrawSkipSource(), bgp.PathNLRI{NLRI: nlri}, isWithdraw, withdrawSkipAttrs(t), time.Now(), false)
}

func withdrawSkipV6Path(t testing.TB, isWithdraw bool) *Path {
	t.Helper()
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:db8:99::/48"))
	require.NoError(t, err)
	mp, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{{NLRI: nlri}}, netip.MustParseAddr("2001:db8::9"))
	require.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{65010, 65020})}),
		mp,
		bgp.NewPathAttributeMultiExitDisc(10),
		bgp.NewPathAttributeCommunities([]uint32{65010<<16 | 1}),
	}
	return NewPath(bgp.RF_IPv6_UC, withdrawSkipSource(), bgp.PathNLRI{NLRI: nlri}, isWithdraw, attrs, time.Now(), false)
}

func serializeAttrList(t testing.TB, p *Path) []byte {
	t.Helper()
	buf := []byte{}
	for _, a := range p.GetPathAttrs() {
		b, err := a.Serialize()
		require.NoError(t, err)
		buf = append(buf, b...)
	}
	return buf
}

// TestUpdatePathAttrsWithdrawSkip is the R-256 mutation pin pair:
//
//   - the withdraw leg must SKIP the rewrite (kills a mutant that removes
//     the skip: the iBGP RR rewrite would add LOCAL_PREF, ORIGINATOR_ID and
//     CLUSTER_LIST, all asserted absent);
//   - the announce leg must NOT skip (kills a mutant that fires the skip on
//     announces: the same additions are asserted present).
func TestUpdatePathAttrsWithdrawSkip(t *testing.T) {
	global := withdrawSkipGlobal()
	rr := withdrawSkipIBGPRRPeer()

	withdraw := withdrawSkipV4Path(t, true)
	got := UpdatePathAttrs(logger, global, rr, withdraw)

	// The clone stays: a distinct, peer-owned object with identity intact.
	require.NotNil(t, got)
	assert.NotSame(t, withdraw, got, "the per-peer clone must survive the skip")
	assert.True(t, got.IsWithdraw)
	assert.Equal(t, withdraw.GetLocalKey(), got.GetLocalKey())
	assert.Equal(t, withdraw.LocalID(), got.LocalID())

	// Attributes byte-identical to the original's: no per-peer rewrite ran.
	assert.Equal(t, serializeAttrList(t, withdraw), serializeAttrList(t, got),
		"withdraw-leg attributes must not be rewritten")
	assert.Nil(t, got.getPathAttr(bgp.BGP_ATTR_TYPE_LOCAL_PREF), "iBGP default LOCAL_PREF must not be built on a withdraw")
	assert.Nil(t, got.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGINATOR_ID), "ORIGINATOR_ID must not be built on a withdraw")
	assert.Nil(t, got.getPathAttr(bgp.BGP_ATTR_TYPE_CLUSTER_LIST), "CLUSTER_LIST must not be built on a withdraw")

	// The announce leg through the same peer must still rewrite.
	announce := withdrawSkipV4Path(t, false)
	gotA := UpdatePathAttrs(logger, global, rr, announce)
	require.NotNil(t, gotA)
	assert.NotNil(t, gotA.getPathAttr(bgp.BGP_ATTR_TYPE_LOCAL_PREF), "announce leg must still build the iBGP default LOCAL_PREF")
	assert.NotNil(t, gotA.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGINATOR_ID), "announce leg must still build ORIGINATOR_ID")
	assert.NotNil(t, gotA.getPathAttr(bgp.BGP_ATTR_TYPE_CLUSTER_LIST), "announce leg must still build CLUSTER_LIST")

	// eBGP shape: the withdraw keeps AS_PATH/nexthop/MED untouched while
	// the announce still gets the full eBGP rewrite.
	ebgp := withdrawSkipEBGPPeer()
	gotW := UpdatePathAttrs(logger, global, ebgp, withdrawSkipV4Path(t, true))
	assert.Equal(t, []uint32{65010, 65020}, gotW.GetAsSeqList(), "withdraw AS_PATH must not be prepended")
	assert.Equal(t, netip.MustParseAddr("10.0.0.9"), gotW.GetNexthop(), "withdraw nexthop must not be rewritten")
	assert.NotNil(t, gotW.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC), "withdraw MED must not be dropped")
	gotE := UpdatePathAttrs(logger, global, ebgp, withdrawSkipV4Path(t, false))
	assert.Equal(t, []uint32{65000, 65010, 65020}, gotE.GetAsSeqList(), "announce AS_PATH must still be prepended")
	assert.Equal(t, ebgp.LocalAddress, gotE.GetNexthop(), "announce nexthop must still be rewritten")
	assert.Nil(t, gotE.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC), "announce MED must still be dropped for eBGP")

	// Route-server clients keep their pre-existing early-out: the ORIGINAL
	// object comes back uncloned, withdraw or not.
	rs := withdrawSkipEBGPPeer()
	rs.RouteServerClient = true
	w := withdrawSkipV4Path(t, true)
	assert.Same(t, w, UpdatePathAttrs(logger, global, rs, w))
	a := withdrawSkipV4Path(t, false)
	assert.Same(t, a, UpdatePathAttrs(logger, global, rs, a))
}

// TestUpdatePathAttrsWithdrawCloneIsolation pins why the clone must stay:
// downstream per-peer mutation (postFilterpath's RemoveLocalPref delPathAttr
// overlay is the live example) must land on the peer-owned clone, never on
// the shared original.
func TestUpdatePathAttrsWithdrawCloneIsolation(t *testing.T) {
	global := withdrawSkipGlobal()
	ebgp := withdrawSkipEBGPPeer()

	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.99.0.0/24"))
	require.NoError(t, err)
	attrs := append(withdrawSkipAttrs(t), bgp.NewPathAttributeLocalPref(200))
	original := NewPath(bgp.RF_IPv4_UC, withdrawSkipSource(), bgp.PathNLRI{NLRI: nlri}, true, attrs, time.Now(), false)

	got := UpdatePathAttrs(logger, global, ebgp, original)
	require.NotNil(t, got.getPathAttr(bgp.BGP_ATTR_TYPE_LOCAL_PREF))

	got.RemoveLocalPref()
	assert.Nil(t, got.getPathAttr(bgp.BGP_ATTR_TYPE_LOCAL_PREF), "per-peer mutation must land on the clone")
	assert.NotNil(t, original.getPathAttr(bgp.BGP_ATTR_TYPE_LOCAL_PREF), "per-peer mutation must not leak to the original")
}

// TestUpdatePathAttrsWithdrawWireEquivalence pins that the skip cannot
// change a single wire byte for a previously-advertised path's withdraw, v4
// and MP alike. The pre-R-256 baseline is reproduced exactly by rewriting
// the withdraw's announce twin and re-flagging the clone (the rewrite body
// never reads IsWithdraw, so that is the identical code path the old
// withdraw leg executed); the raw synthetic-old shape (old.Clone(true),
// which has always bypassed UpdatePathAttrs) is compared too.
func TestUpdatePathAttrsWithdrawWireEquivalence(t *testing.T) {
	global := withdrawSkipGlobal()

	serializeMsg := func(p *Path) []byte {
		msgs := CreateUpdateMsgFromPaths([]*Path{p})
		require.Len(t, msgs, 1)
		b, err := msgs[0].Serialize()
		require.NoError(t, err)
		return b
	}

	for _, tc := range []struct {
		name     string
		withdraw func(testing.TB, bool) *Path
	}{
		{name: "ipv4-unicast", withdraw: func(tb testing.TB, w bool) *Path { return withdrawSkipV4Path(tb, w) }},
		{name: "ipv6-unicast-mp", withdraw: func(tb testing.TB, w bool) *Path { return withdrawSkipV6Path(tb, w) }},
	} {
		for _, peer := range []struct {
			name string
			info *PeerInfo
		}{
			{name: "ibgp-rr", info: withdrawSkipIBGPRRPeer()},
			{name: "ebgp", info: withdrawSkipEBGPPeer()},
		} {
			t.Run(tc.name+"/"+peer.name, func(t *testing.T) {
				skipped := UpdatePathAttrs(logger, global, peer.info, tc.withdraw(t, true))
				oldStyle := UpdatePathAttrs(logger, global, peer.info, tc.withdraw(t, false)).Clone(true)
				syntheticOld := tc.withdraw(t, true).Clone(true)

				want := serializeMsg(oldStyle)
				assert.Equal(t, want, serializeMsg(skipped),
					"withdraw wire bytes must be identical with and without the attr rewrite")
				assert.Equal(t, want, serializeMsg(syntheticOld),
					"the synthetic-old withdraw shape must already be wire-identical")
			})
		}
	}
}

// TestUpdatePathAttrsWithdrawWireEquivalenceAddPath is the production-shape
// pin (bendrr runs ADD-PATH send fleet-wide): the ADD-PATH withdraw encoders
// (packerV4.pack / packerMP.pack) are the only places a withdraw's localID
// reaches the wire, and they are exercised only under a MarshallingOption
// with AddPath send. Two withdraws with distinct path IDs must batch into
// ONE byte-identical message with and without the attr rewrite.
//
// Note this test cannot (and should not) kill the mutant that fires the
// skip on the announce leg: withdraw wire bytes never depend on attributes,
// so both sides of the comparison collapse to the same NLRI-only message
// under that mutant too. TestUpdatePathAttrsWithdrawSkip's announce-leg
// assertions own that mutant.
func TestUpdatePathAttrsWithdrawWireEquivalenceAddPath(t *testing.T) {
	global := withdrawSkipGlobal()

	mkV4 := func(tb testing.TB, prefix string, id uint32, isWithdraw bool) *Path {
		tb.Helper()
		nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
		require.NoError(tb, err)
		p := NewPath(bgp.RF_IPv4_UC, withdrawSkipSource(), bgp.PathNLRI{NLRI: nlri}, isWithdraw, withdrawSkipAttrs(tb), time.Now(), false)
		p.localID = id
		return p
	}
	mkV6 := func(tb testing.TB, prefix string, id uint32, isWithdraw bool) *Path {
		tb.Helper()
		nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
		require.NoError(tb, err)
		mp, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{{NLRI: nlri}}, netip.MustParseAddr("2001:db8::9"))
		require.NoError(tb, err)
		attrs := []bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(0),
			bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{65010, 65020})}),
			mp,
		}
		p := NewPath(bgp.RF_IPv6_UC, withdrawSkipSource(), bgp.PathNLRI{NLRI: nlri}, isWithdraw, attrs, time.Now(), false)
		p.localID = id
		return p
	}

	for _, tc := range []struct {
		name     string
		family   bgp.Family
		prefixes [2]string
		mk       func(testing.TB, string, uint32, bool) *Path
	}{
		{name: "ipv4-unicast", family: bgp.RF_IPv4_UC, prefixes: [2]string{"10.99.0.0/24", "10.99.1.0/24"}, mk: mkV4},
		{name: "ipv6-unicast-mp", family: bgp.RF_IPv6_UC, prefixes: [2]string{"2001:db8:99::/48", "2001:db8:9a::/48"}, mk: mkV6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opt := &bgp.MarshallingOption{AddPath: map[bgp.Family]bgp.BGPAddPathMode{tc.family: bgp.BGP_ADD_PATH_SEND}}
			info := withdrawSkipIBGPRRPeer()

			build := func(withdrawLeg bool) []*Path {
				out := make([]*Path, 0, 2)
				for i, prefix := range tc.prefixes {
					id := uint32(i + 1)
					if withdrawLeg {
						out = append(out, UpdatePathAttrs(logger, global, info, tc.mk(t, prefix, id, true)))
					} else {
						// pre-R-256 baseline: full rewrite via the announce
						// twin, clone re-flagged withdraw (Clone preserves
						// localID).
						out = append(out, UpdatePathAttrs(logger, global, info, tc.mk(t, prefix, id, false)).Clone(true))
					}
				}
				return out
			}

			serialize := func(paths []*Path, opts ...*bgp.MarshallingOption) []byte {
				msgs := CreateUpdateMsgFromPaths(paths, opts...)
				require.Len(t, msgs, 1, "both withdraws must batch into one message")
				b, err := msgs[0].Serialize(opts...)
				require.NoError(t, err)
				return b
			}

			skipped := serialize(build(true), opt)
			baseline := serialize(build(false), opt)
			assert.Equal(t, baseline, skipped,
				"ADD-PATH batched withdraw wire bytes must be identical with and without the attr rewrite")

			// Pin that the ADD-PATH encoder actually engaged: the same
			// paths serialized without the option must differ (each NLRI
			// loses its 4-byte path identifier).
			assert.NotEqual(t, serialize(build(true)), skipped,
				"ADD-PATH option must change the wire encoding, or this test exercises nothing")
		})
	}
}

// BenchmarkUpdatePathAttrsWithdrawLeg measures the R-256 win. The
// "rewrite-preR256" leg runs the announce twin through the full rewrite —
// the rewrite body never reads IsWithdraw, so that is byte-for-byte the
// work the pre-R-256 withdraw leg performed. iBGP RR client peer, bendrr
// injected-path attribute shape (the row's measurement conditions).
func BenchmarkUpdatePathAttrsWithdrawLeg(b *testing.B) {
	global := withdrawSkipGlobal()
	rr := withdrawSkipIBGPRRPeer()
	withdraw := withdrawSkipV4Path(b, true)
	announceTwin := withdrawSkipV4Path(b, false)

	b.Run("skip", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if p := UpdatePathAttrs(logger, global, rr, withdraw); p == nil {
				b.Fatal("nil result")
			}
		}
	})
	b.Run("rewrite-preR256", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if p := UpdatePathAttrs(logger, global, rr, announceTwin); p == nil {
				b.Fatal("nil result")
			}
		}
	})
}
