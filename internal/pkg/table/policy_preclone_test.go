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

// Tests and benchmarks for ProvablyRejectsPreClone (Bendrr R-230 phase-2).
// The differential test and the gate-chain benchmark are deterministic
// adaptations of the round-1 review's throwaway artifacts.

import (
	"fmt"
	"math/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// buildBendrrGateChain reproduces the production ScopedExport gate chain
// shape (bendrr pkg/gobgp/export.go), shared by every non-RS peer under the
// GLOBAL_RIB_NAME assignment:
//
//	guard : neighbor-set{inventory} INVERT -> reject
//	scope1: neighbor-set{scope} ANY + prefix-set{canary} ANY -> accept
//	scope2: neighbor-set{scope} ANY -> reject
//	allow : neighbor-set{inventory} ANY -> accept
//	default: reject (fail-closed)
func buildBendrrGateChain(t testing.TB) *RoutingPolicy {
	t.Helper()
	rp := NewRoutingPolicy(logger)
	if err := rp.Reset(&oc.RoutingPolicy{}, nil); err != nil {
		t.Fatal(err)
	}
	inv, err := NewNeighborSet(oc.NeighborSet{
		NeighborSetName:  "inventory",
		NeighborInfoList: []string{"192.168.0.2/32", "192.168.0.3/32"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := rp.AddDefinedSet(inv, false); err != nil {
		t.Fatal(err)
	}
	scope, err := NewNeighborSet(oc.NeighborSet{
		NeighborSetName:  "scope",
		NeighborInfoList: []string{"192.168.0.2/32"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := rp.AddDefinedSet(scope, false); err != nil {
		t.Fatal(err)
	}
	canary, err := NewPrefixSet(oc.PrefixSet{
		PrefixSetName: "canary",
		PrefixList:    []oc.Prefix{{IpPrefix: netip.MustParsePrefix("10.10.10.0/24")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := rp.AddDefinedSet(canary, false); err != nil {
		t.Fatal(err)
	}
	mk := func(name string, st []oc.Statement) {
		p, err := NewPolicy(oc.PolicyDefinition{Name: name, Statements: st})
		if err != nil {
			t.Fatal(err)
		}
		if err := rp.AddPolicy(p, false); err != nil {
			t.Fatal(err)
		}
	}
	mk("guard", []oc.Statement{{
		Name: "reject-unknown",
		Conditions: oc.Conditions{MatchNeighborSet: oc.MatchNeighborSet{
			NeighborSet: "inventory", MatchSetOptions: oc.MATCH_SET_OPTIONS_RESTRICTED_TYPE_INVERT,
		}},
		Actions: oc.Actions{RouteDisposition: oc.ROUTE_DISPOSITION_REJECT_ROUTE},
	}})
	mk("scope", []oc.Statement{
		{
			Name: "scope-accept",
			Conditions: oc.Conditions{
				MatchNeighborSet: oc.MatchNeighborSet{NeighborSet: "scope"},
				MatchPrefixSet:   oc.MatchPrefixSet{PrefixSet: "canary"},
			},
			Actions: oc.Actions{RouteDisposition: oc.ROUTE_DISPOSITION_ACCEPT_ROUTE},
		},
		{
			Name:       "scope-reject",
			Conditions: oc.Conditions{MatchNeighborSet: oc.MatchNeighborSet{NeighborSet: "scope"}},
			Actions:    oc.Actions{RouteDisposition: oc.ROUTE_DISPOSITION_REJECT_ROUTE},
		},
	})
	mk("allow", []oc.Statement{{
		Name:       "allow-routers",
		Conditions: oc.Conditions{MatchNeighborSet: oc.MatchNeighborSet{NeighborSet: "inventory"}},
		Actions:    oc.Actions{RouteDisposition: oc.ROUTE_DISPOSITION_ACCEPT_ROUTE},
	}})
	if err := rp.AddPolicyAssignment(GLOBAL_RIB_NAME, POLICY_DIRECTION_EXPORT,
		[]*oc.PolicyDefinition{{Name: "guard"}, {Name: "scope"}, {Name: "allow"}},
		ROUTE_TYPE_REJECT); err != nil {
		t.Fatal(err)
	}
	return rp
}

func gateChainPeerInfo(address string) *PeerInfo {
	return &PeerInfo{
		AS:           3,
		LocalAS:      1,
		Address:      netip.MustParseAddr(address),
		LocalAddress: netip.MustParseAddr("1.1.1.1"),
		ID:           netip.MustParseAddr(address),
		LocalID:      netip.MustParseAddr("1.1.1.1"),
		PeerType:     oc.PEER_TYPE_EXTERNAL,
	}
}

func gateChainPath(t testing.TB, prefix string) *Path {
	t.Helper()
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
	if err != nil {
		t.Fatal(err)
	}
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.9"))
	if err != nil {
		t.Fatal(err)
	}
	src := &PeerInfo{AS: 2, LocalAS: 1, Address: netip.MustParseAddr("192.168.0.1"), ID: netip.MustParseAddr("192.168.0.1"), LocalID: netip.MustParseAddr("1.1.1.1")}
	return NewPath(bgp.RF_IPv4_UC, src, bgp.PathNLRI{NLRI: nlri}, false, []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{2})}),
		nh,
	}, time.Now(), false)
}

// TestProvablyRejectsGateChainShape pins the prover's verdicts against the
// production gate chain directly at the table layer: the scoped probe peer's
// non-canary reject is provable, the canary accept and the inventory
// router's accept are not, and an unknown neighbor's guard reject is
// provable (the guard is neighbor-INVERT, still whitelisted).
func TestProvablyRejectsGateChainShape(t *testing.T) {
	rp := buildBendrrGateChain(t)
	path := gateChainPath(t, "10.99.0.0/24")
	canary := gateChainPath(t, "10.10.10.0/24")

	probeOpts := &PolicyOptions{Info: gateChainPeerInfo("192.168.0.2"), OldNextHop: path.GetNexthop()}
	routerOpts := &PolicyOptions{Info: gateChainPeerInfo("192.168.0.3"), OldNextHop: path.GetNexthop()}
	strangerOpts := &PolicyOptions{Info: gateChainPeerInfo("192.168.0.9"), OldNextHop: path.GetNexthop()}

	if !rp.ProvablyRejectsPreClone(GLOBAL_RIB_NAME, POLICY_DIRECTION_EXPORT, path, probeOpts) {
		t.Fatal("probe non-canary reject must be provable")
	}
	if rp.ProvablyRejectsPreClone(GLOBAL_RIB_NAME, POLICY_DIRECTION_EXPORT, canary, probeOpts) {
		t.Fatal("probe canary accept must not be provable")
	}
	if rp.ProvablyRejectsPreClone(GLOBAL_RIB_NAME, POLICY_DIRECTION_EXPORT, path, routerOpts) {
		t.Fatal("inventory router accept must not be provable")
	}
	if !rp.ProvablyRejectsPreClone(GLOBAL_RIB_NAME, POLICY_DIRECTION_EXPORT, path, strangerOpts) {
		t.Fatal("guard reject for an unknown neighbor must be provable")
	}
	if rp.ProvablyRejectsPreClone(GLOBAL_RIB_NAME, POLICY_DIRECTION_EXPORT, path.Clone(true), probeOpts) {
		t.Fatal("withdraws must never be provable")
	}
}

// BenchmarkPrecloneGateChain measures both legs of the R-230 phase-2 trade
// against the production gate chain shape:
//
//   - rejected leg: the prover (what the short-circuit pays) versus the
//     UpdatePathAttrs clone + ApplyPolicy walk it replaces;
//   - accepted leg: the prover as PURE ADDED COST (it walks the chain to
//     the accept and returns false; the full pipeline then runs anyway)
//     versus that full-pipeline baseline.
//
// The break-even accepted:rejected ratio is (full-reject − prover-reject) /
// prover-accept; see the phase-2 review-round commit message for the
// measured numbers and the rig-ratio waiver argument.
func BenchmarkPrecloneGateChain(b *testing.B) {
	rp := buildBendrrGateChain(b)
	gConf := &oc.Global{Config: oc.GlobalConfig{As: 1, RouterId: netip.MustParseAddr("1.1.1.1")}}
	path := gateChainPath(b, "10.99.0.0/24")
	probe := gateChainPeerInfo("192.168.0.2")
	router := gateChainPeerInfo("192.168.0.3")
	probeOpts := &PolicyOptions{Info: probe, OldNextHop: path.GetNexthop()}
	routerOpts := &PolicyOptions{Info: router, OldNextHop: path.GetNexthop()}

	b.Run("rejected-leg/prover-short-circuit", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if !rp.ProvablyRejectsPreClone(GLOBAL_RIB_NAME, POLICY_DIRECTION_EXPORT, path, probeOpts) {
				b.Fatal("expected a provable reject")
			}
		}
	})
	b.Run("rejected-leg/full-pipeline", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			cloned := UpdatePathAttrs(logger, gConf, probe, path)
			if rp.ApplyPolicy(GLOBAL_RIB_NAME, POLICY_DIRECTION_EXPORT, cloned, probeOpts) != nil {
				b.Fatal("expected a reject")
			}
		}
	})
	b.Run("accepted-leg/prover-overhead", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if rp.ProvablyRejectsPreClone(GLOBAL_RIB_NAME, POLICY_DIRECTION_EXPORT, path, routerOpts) {
				b.Fatal("unexpected proof")
			}
		}
	})
	b.Run("accepted-leg/full-pipeline", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			cloned := UpdatePathAttrs(logger, gConf, router, path)
			if rp.ApplyPolicy(GLOBAL_RIB_NAME, POLICY_DIRECTION_EXPORT, cloned, routerOpts) == nil {
				b.Fatal("expected an accept")
			}
		}
	})
}

// TestProvablyRejectsPreCloneDifferential is a seeded, bounded differential
// check (deterministic subset of the round-1 review's 32k-sample randomized
// run, which found zero mismatches): the prover must never claim "reject"
// when the real pipeline — UpdatePathAttrs clone then ApplyPolicy — returns
// a non-nil path. Policies mix whitelisted conditions (prefix/neighbor/
// afi-safi, ANY and INVERT), non-whitelisted conditions, mod actions, and
// all three dispositions; paths mix families, attributes, peer types, RR
// and RS client flags, and occasionally an unassigned policy id.
func TestProvablyRejectsPreCloneDifferential(t *testing.T) {
	rnd := rand.New(rand.NewSource(1))
	gConf := &oc.Global{Config: oc.GlobalConfig{As: 65000, RouterId: netip.MustParseAddr("10.0.0.254")}}

	prefixes4 := []string{"10.10.10.0/24", "10.99.0.0/24", "10.10.0.0/16", "192.0.2.0/24"}
	prefixes6 := []string{"2001:db8::/32", "2001:db8:1::/48"}
	neighbors := []string{"10.0.0.1/32", "10.0.0.2/32", "0.0.0.0/0"}

	pick := func(opts ...string) string { return opts[rnd.Intn(len(opts))] }
	pickMSO := func() oc.MatchSetOptionsRestrictedType {
		if rnd.Intn(4) == 0 {
			return oc.MATCH_SET_OPTIONS_RESTRICTED_TYPE_INVERT
		}
		return oc.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY
	}

	total, proven := 0, 0

	for iter := 0; iter < 500; iter++ {
		r := NewRoutingPolicy(logger)
		if err := r.Reset(&oc.RoutingPolicy{}, nil); err != nil {
			t.Fatal(err)
		}

		ps4, err := NewPrefixSet(oc.PrefixSet{
			PrefixSetName: "ps4",
			PrefixList: []oc.Prefix{
				{IpPrefix: netip.MustParsePrefix(prefixes4[rnd.Intn(len(prefixes4))]), MasklengthRange: pick("", "24..32", "16..24")},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := r.AddDefinedSet(ps4, false); err != nil {
			t.Fatal(err)
		}
		ps6, err := NewPrefixSet(oc.PrefixSet{
			PrefixSetName: "ps6",
			PrefixList:    []oc.Prefix{{IpPrefix: netip.MustParsePrefix(prefixes6[rnd.Intn(len(prefixes6))])}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := r.AddDefinedSet(ps6, false); err != nil {
			t.Fatal(err)
		}
		ns, err := NewNeighborSet(oc.NeighborSet{
			NeighborSetName:  "ns",
			NeighborInfoList: []string{neighbors[rnd.Intn(len(neighbors))]},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := r.AddDefinedSet(ns, false); err != nil {
			t.Fatal(err)
		}
		cs, err := NewCommunitySet(oc.CommunitySet{CommunitySetName: "cs", CommunityList: []string{"100:100"}})
		if err != nil {
			t.Fatal(err)
		}
		if err := r.AddDefinedSet(cs, false); err != nil {
			t.Fatal(err)
		}
		aps, err := NewAsPathSet(oc.AsPathSet{AsPathSetName: "aps", AsPathList: []string{"^65001"}})
		if err != nil {
			t.Fatal(err)
		}
		if err := r.AddDefinedSet(aps, false); err != nil {
			t.Fatal(err)
		}

		npol := 1 + rnd.Intn(2)
		defs := make([]*oc.PolicyDefinition, 0, npol)
		for pi := 0; pi < npol; pi++ {
			nstmt := 1 + rnd.Intn(4)
			stmts := make([]oc.Statement, 0, nstmt)
			for si := 0; si < nstmt; si++ {
				st := oc.Statement{Name: fmt.Sprintf("p%d_s%d", pi, si)}
				if rnd.Intn(2) == 0 {
					st.Conditions.MatchPrefixSet = oc.MatchPrefixSet{
						PrefixSet:       pick("ps4", "ps6"),
						MatchSetOptions: pickMSO(),
					}
				}
				if rnd.Intn(3) == 0 {
					st.Conditions.MatchNeighborSet = oc.MatchNeighborSet{
						NeighborSet:     "ns",
						MatchSetOptions: pickMSO(),
					}
				}
				if rnd.Intn(3) == 0 {
					st.Conditions.BgpConditions.AfiSafiInList = []oc.AfiSafiType{oc.AFI_SAFI_TYPE_IPV4_UNICAST}
				}
				// Non-whitelisted conditions: must force "unknown".
				switch rnd.Intn(8) {
				case 0:
					st.Conditions.BgpConditions.MatchCommunitySet = oc.MatchCommunitySet{CommunitySet: "cs"}
				case 1:
					st.Conditions.BgpConditions.MatchAsPathSet = oc.MatchAsPathSet{AsPathSet: "aps"}
				case 2:
					st.Conditions.BgpConditions.AsPathLength = oc.AsPathLength{Operator: oc.ATTRIBUTE_COMPARISON_GE, Value: 1}
				case 3:
					st.Conditions.BgpConditions.MedEq = 10
				case 4:
					st.Conditions.BgpConditions.LocalPrefEq = 100
				case 5:
					st.Conditions.BgpConditions.NextHopInList = []netip.Addr{netip.MustParseAddr("10.0.0.9")}
				}
				if rnd.Intn(2) == 0 {
					st.Actions.BgpActions.SetCommunity = oc.SetCommunity{
						Options:            "add",
						SetCommunityMethod: oc.SetCommunityMethod{CommunitiesList: []string{"100:100"}},
					}
				}
				if rnd.Intn(3) == 0 {
					st.Actions.BgpActions.SetAsPathPrepend = oc.SetAsPathPrepend{As: "65001", RepeatN: 2}
				}
				if rnd.Intn(3) == 0 {
					st.Actions.BgpActions.SetMed = oc.BgpSetMedType("10")
				}
				if rnd.Intn(3) == 0 {
					st.Actions.BgpActions.SetLocalPref = 100
				}
				if rnd.Intn(4) == 0 {
					st.Actions.BgpActions.SetNextHop = oc.BgpNextHopType("10.9.9.9")
				}
				if rnd.Intn(4) == 0 {
					st.Actions.BgpActions.SetRouteOrigin = oc.BGP_ORIGIN_ATTR_TYPE_EGP
				}
				switch rnd.Intn(3) {
				case 0:
					st.Actions.RouteDisposition = oc.ROUTE_DISPOSITION_ACCEPT_ROUTE
				case 1:
					st.Actions.RouteDisposition = oc.ROUTE_DISPOSITION_REJECT_ROUTE
				default:
					st.Actions.RouteDisposition = oc.ROUTE_DISPOSITION_NONE
				}
				stmts = append(stmts, st)
			}
			def := oc.PolicyDefinition{Name: fmt.Sprintf("pol%d", pi), Statements: stmts}
			pol, err := NewPolicy(def)
			if err != nil {
				t.Fatal(err)
			}
			if err := r.AddPolicy(pol, false); err != nil {
				t.Fatal(err)
			}
			defs = append(defs, &oc.PolicyDefinition{Name: def.Name})
		}

		id := "g"
		if rnd.Intn(10) != 0 { // sometimes leave the id unassigned
			def := ROUTE_TYPE_REJECT
			switch rnd.Intn(3) {
			case 0:
				def = ROUTE_TYPE_ACCEPT
			case 1:
				def = ROUTE_TYPE_NONE
			}
			if err := r.AddPolicyAssignment(id, POLICY_DIRECTION_EXPORT, defs, def); err != nil {
				t.Fatal(err)
			}
		}

		for k := 0; k < 8; k++ {
			srcAddr := netip.MustParseAddr(pick("10.0.0.1", "10.0.0.2", "10.0.0.3"))
			src := &PeerInfo{AS: 65001, Address: srcAddr, ID: netip.MustParseAddr("1.1.1.1"), LocalID: netip.MustParseAddr("2.2.2.2")}

			v6 := rnd.Intn(4) == 0
			var nlri bgp.NLRI
			var family bgp.Family
			attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}
			attrs = append(attrs, bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{65001})}))
			if v6 {
				n, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefixes6[rnd.Intn(len(prefixes6))]))
				nlri = n
				family = bgp.RF_IPv6_UC
				mp, _ := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{{NLRI: n}}, netip.MustParseAddr("2001:db8::1"))
				attrs = append(attrs, mp)
			} else {
				n, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefixes4[rnd.Intn(len(prefixes4))]))
				nlri = n
				family = bgp.RF_IPv4_UC
				nh, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.9"))
				attrs = append(attrs, nh)
			}
			if rnd.Intn(2) == 0 {
				attrs = append(attrs, bgp.NewPathAttributeCommunities([]uint32{100<<16 | 100}))
			}
			if rnd.Intn(2) == 0 {
				attrs = append(attrs, bgp.NewPathAttributeMultiExitDisc(10))
			}
			if rnd.Intn(2) == 0 {
				attrs = append(attrs, bgp.NewPathAttributeLocalPref(100))
			}

			p := NewPath(family, src, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)

			peerInfo := &PeerInfo{
				AS:                      65002,
				Address:                 netip.MustParseAddr(pick("10.0.0.1", "10.0.0.2", "10.0.0.3")),
				LocalAS:                 65000,
				LocalAddress:            netip.MustParseAddr("10.0.0.254"),
				ID:                      netip.MustParseAddr("3.3.3.3"),
				LocalID:                 netip.MustParseAddr("2.2.2.2"),
				RouteReflectorClient:    rnd.Intn(4) == 0,
				RouteReflectorClusterID: netip.MustParseAddr("9.9.9.9"),
			}
			if rnd.Intn(2) == 0 {
				peerInfo.PeerType = oc.PEER_TYPE_EXTERNAL
			} else {
				peerInfo.PeerType = oc.PEER_TYPE_INTERNAL
			}
			if rnd.Intn(8) == 0 {
				peerInfo.RouteServerClient = true
			}

			options := &PolicyOptions{Info: peerInfo, OldNextHop: p.GetNexthop()}

			total++
			pr := r.ProvablyRejectsPreClone(id, POLICY_DIRECTION_EXPORT, p, options)
			cloned := UpdatePathAttrs(logger, gConf, peerInfo, p)
			real := r.ApplyPolicy(id, POLICY_DIRECTION_EXPORT, cloned, options)
			if pr {
				proven++
				if real != nil {
					t.Errorf("iter %d sample %d: prover said REJECT but ApplyPolicy accepted: %s", iter, k, real)
				}
			}
		}
	}
	t.Logf("total=%d proven=%d", total, proven)
	if proven == 0 {
		t.Fatal("prover never fired; test is vacuous")
	}
}
