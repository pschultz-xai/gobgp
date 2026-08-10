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

// TestProvablyRejectsPreCloneDifferential is a seeded differential check in
// the round-1 review's randomized style (that review's throwaway 32k-sample
// run — over the pre-RTC corpus — found zero mismatches; this corpus is a
// different draw at the same 32k size): the prover must never claim
// "reject" when the real pipeline — UpdatePathAttrs clone then ApplyPolicy —
// returns a non-nil path. Policies mix whitelisted conditions (prefix/
// neighbor/afi-safi, ANY and INVERT), non-whitelisted conditions
// (community/as-path/ext-community and attribute comparisons), mod actions
// (including ext-community, the attribute that 6934f7d5 contrasts rtc-prefix
// against), and all three dispositions; paths mix families (IPv4-UC,
// IPv6-UC, and — since 6934f7d5 taught PrefixCondition to match the Route
// Target inside an RTC NLRI — RTC across /0, /32, intermediate 33..95 and
// /96 depths, Bendrr R-258), attributes, peer types, RR and RS client
// flags, and occasionally an unassigned policy id.
func TestProvablyRejectsPreCloneDifferential(t *testing.T) {
	rnd := rand.New(rand.NewSource(1))
	gConf := &oc.Global{Config: oc.GlobalConfig{As: 65000, RouterId: netip.MustParseAddr("10.0.0.254")}}

	prefixes4 := []string{"10.10.10.0/24", "10.99.0.0/24", "10.10.0.0/16", "192.0.2.0/24"}
	prefixes6 := []string{"2001:db8::/32", "2001:db8:1::/48"}
	// rtc-prefix set entries spanning the trie-key depths — exact /96,
	// origin-as + RT AS /64, origin-as only /32, match-all /0 — then a /64
	// carrying non-zero bits below the mask (ParseRTCPrefix builds the trie
	// key unmasked, so that shape must behave like its masked sibling), and
	// /96 entries in the IPv4-specific and 4-octet-AS RT encodings so those
	// ExtCommRouteTargetKey branches can produce positive deep matches, not
	// just misses; see TestPrefixSetMatchRtcPrefix.
	prefixesRtc := []string{
		"65001:65000:100/96", "65001:65000:0/64", "65001:0:0/32", "0:0:0/0",
		"65001:65000:100/64", "65001:1.2.3.4:100/96", "65001:100.1000:100/96",
	}
	neighbors := []string{"10.0.0.1/32", "10.0.0.2/32", "0.0.0.0/0"}
	// All three Route Target encodings ExtCommRouteTargetKey supports:
	// 2-octet AS, IPv4-address and 4-octet AS specific.
	routeTargets := []string{"65000:100", "65000:200", "65001:100", "1.2.3.4:100", "100.1000:100"}

	pick := func(opts ...string) string { return opts[rnd.Intn(len(opts))] }
	pickMSO := func() oc.MatchSetOptionsRestrictedType {
		if rnd.Intn(4) == 0 {
			return oc.MATCH_SET_OPTIONS_RESTRICTED_TYPE_INVERT
		}
		return oc.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY
	}
	mustRT := func(s string) bgp.ExtendedCommunityInterface {
		rt, err := bgp.ParseRouteTarget(s)
		if err != nil {
			t.Fatal(err)
		}
		return rt
	}

	total, proven := 0, 0
	totalRtc, provenRtc := 0, 0
	rtcReachHit, rtcReachMiss := 0, 0
	provenViaRtcPrefix, acceptPinViaRtcPrefix := 0, 0

	for iter := 0; iter < 4000; iter++ {
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
		psrtc, err := NewPrefixSet(oc.PrefixSet{
			PrefixSetName: "psrtc",
			PrefixList: []oc.Prefix{
				{RtcPrefix: prefixesRtc[rnd.Intn(len(prefixesRtc))], MasklengthRange: pick("", "96..96", "32..96", "0..96")},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := r.AddDefinedSet(psrtc, false); err != nil {
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
		ecs, err := NewExtCommunitySet(oc.ExtCommunitySet{ExtCommunitySetName: "ecs", ExtCommunityList: []string{"rt:65000:100"}})
		if err != nil {
			t.Fatal(err)
		}
		if err := r.AddDefinedSet(ecs, false); err != nil {
			t.Fatal(err)
		}
		lcs, err := NewLargeCommunitySet(oc.LargeCommunitySet{LargeCommunitySetName: "lcs", LargeCommunityList: []string{"100:100:100"}})
		if err != nil {
			t.Fatal(err)
		}
		if err := r.AddDefinedSet(lcs, false); err != nil {
			t.Fatal(err)
		}

		// R-258 reach guarantee: in a third of the iterations the FIRST
		// statement of the FIRST policy is a whitelisted-only rtc-prefix
		// statement, so the prover's walk — which starts there — evaluates
		// the RTC branch of PrefixCondition before anything can abort or
		// terminate it. Leaving reach to the random statement mix is not
		// enough: 7/8 of random statements carry a non-whitelisted
		// condition that aborts the walk, so the prover reached an
		// rtc-prefix statement in only ~170 of 32k samples (round-2 review
		// measurement).
		rtcFirst := rnd.Intn(3) == 0
		rtcFirstInvert := false
		var rtcFirstDisp oc.RouteDisposition
		// Deliberately seeded action-then-match head (round-2 review MAJOR
		// B, round-3 MAJOR-1): a leading always-matching NONE statement
		// whose community-family "add" action writes the value that the
		// second statement's matching condition then reads. On the real
		// (cloned) walk the second statement can match a path that lacked
		// the attribute pre-clone — exactly the interaction that makes
		// whitelisting an attribute-reading condition unsound, and it is
		// NOT covered by clone-rewrite differences (UpdatePathAttrs leaves
		// communities, ext-communities and large-communities alone). Left
		// to the random mix this shape coincides ~once per 533k samples;
		// seeded per sibling, a prover wrongly whitelisting any of
		// CommunityCondition/ExtCommunityCondition/LargeCommunityCondition
		// fails the 32k run outright. Note the cost: in trap iterations
		// with an assigned id the prover always aborts at statement 1, so
		// those samples (~19% of the corpus) serve as mutation bait rather
		// than contributing proofs to the main differential.
		trapKind := 0 // 0 = none, 1 = ext-community, 2 = community, 3 = large-community
		if !rtcFirst && rnd.Intn(3) == 0 {
			trapKind = 1 + rnd.Intn(3)
		}
		npol := 1 + rnd.Intn(2)
		defs := make([]*oc.PolicyDefinition, 0, npol)
		for pi := 0; pi < npol; pi++ {
			nstmt := 1 + rnd.Intn(4)
			if trapKind != 0 && pi == 0 && nstmt < 2 {
				nstmt = 2
			}
			stmts := make([]oc.Statement, 0, nstmt)
			for si := 0; si < nstmt; si++ {
				st := oc.Statement{Name: fmt.Sprintf("p%d_s%d", pi, si)}
				if trapKind != 0 && pi == 0 && si == 0 {
					switch trapKind {
					case 1:
						st.Actions.BgpActions.SetExtCommunity = oc.SetExtCommunity{
							Options:               "add",
							SetExtCommunityMethod: oc.SetExtCommunityMethod{CommunitiesList: []string{"rt:65000:100"}},
						}
					case 2:
						st.Actions.BgpActions.SetCommunity = oc.SetCommunity{
							Options:            "add",
							SetCommunityMethod: oc.SetCommunityMethod{CommunitiesList: []string{"100:100"}},
						}
					case 3:
						st.Actions.BgpActions.SetLargeCommunity = oc.SetLargeCommunity{
							Options:                 oc.BGP_SET_COMMUNITY_OPTION_TYPE_ADD,
							SetLargeCommunityMethod: oc.SetLargeCommunityMethod{CommunitiesList: []string{"100:100:100"}},
						}
					}
					st.Actions.RouteDisposition = oc.ROUTE_DISPOSITION_NONE
					stmts = append(stmts, st)
					continue
				}
				if trapKind != 0 && pi == 0 && si == 1 {
					switch trapKind {
					case 1:
						st.Conditions.BgpConditions.MatchExtCommunitySet = oc.MatchExtCommunitySet{ExtCommunitySet: "ecs"}
					case 2:
						st.Conditions.BgpConditions.MatchCommunitySet = oc.MatchCommunitySet{CommunitySet: "cs"}
					case 3:
						st.Conditions.BgpConditions.MatchLargeCommunitySet = oc.MatchLargeCommunitySet{LargeCommunitySet: "lcs"}
					}
					if rnd.Intn(2) == 0 {
						st.Actions.RouteDisposition = oc.ROUTE_DISPOSITION_ACCEPT_ROUTE
					} else {
						st.Actions.RouteDisposition = oc.ROUTE_DISPOSITION_REJECT_ROUTE
					}
					stmts = append(stmts, st)
					continue
				}
				if rtcFirst && pi == 0 && si == 0 {
					mso := pickMSO()
					rtcFirstInvert = mso == oc.MATCH_SET_OPTIONS_RESTRICTED_TYPE_INVERT
					st.Conditions.MatchPrefixSet = oc.MatchPrefixSet{
						PrefixSet:       "psrtc",
						MatchSetOptions: mso,
					}
					switch rnd.Intn(3) {
					case 0:
						rtcFirstDisp = oc.ROUTE_DISPOSITION_ACCEPT_ROUTE
					case 1:
						rtcFirstDisp = oc.ROUTE_DISPOSITION_REJECT_ROUTE
					default:
						rtcFirstDisp = oc.ROUTE_DISPOSITION_NONE
					}
					st.Actions.RouteDisposition = rtcFirstDisp
					stmts = append(stmts, st)
					continue
				}
				if rnd.Intn(2) == 0 {
					st.Conditions.MatchPrefixSet = oc.MatchPrefixSet{
						PrefixSet:       pick("ps4", "ps6", "psrtc"),
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
					afiSafi := oc.AFI_SAFI_TYPE_IPV4_UNICAST
					if rnd.Intn(4) == 0 {
						afiSafi = oc.AFI_SAFI_TYPE_RTC
					}
					st.Conditions.BgpConditions.AfiSafiInList = []oc.AfiSafiType{afiSafi}
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
				case 6:
					// The condition 6934f7d5 contrasts rtc-prefix against: it
					// reads the ext-communities ATTRIBUTE, so it must force
					// "unknown" even though rtc-prefix (NLRI key) is whitelisted.
					st.Conditions.BgpConditions.MatchExtCommunitySet = oc.MatchExtCommunitySet{ExtCommunitySet: "ecs"}
				}
				if rnd.Intn(2) == 0 {
					st.Actions.BgpActions.SetCommunity = oc.SetCommunity{
						Options:            "add",
						SetCommunityMethod: oc.SetCommunityMethod{CommunitiesList: []string{"100:100"}},
					}
				}
				if rnd.Intn(3) == 0 {
					// Attribute-mutating RT write: must not perturb the
					// NLRI-key match of a later rtc-prefix statement.
					st.Actions.BgpActions.SetExtCommunity = oc.SetExtCommunity{
						Options:               "add",
						SetExtCommunityMethod: oc.SetExtCommunityMethod{CommunitiesList: []string{"rt:65000:100"}},
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
		assigned := rnd.Intn(10) != 0 // sometimes leave the id unassigned
		if assigned {
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

			var nlri bgp.NLRI
			var family bgp.Family
			attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}
			attrs = append(attrs, bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{65001})}))
			switch rnd.Intn(8) {
			case 0, 1: // IPv6-UC
				n, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefixes6[rnd.Intn(len(prefixes6))]))
				nlri = n
				family = bgp.RF_IPv6_UC
				mp, _ := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{{NLRI: n}}, netip.MustParseAddr("2001:db8::1"))
				attrs = append(attrs, mp)
			case 2, 3: // RTC (Bendrr R-258)
				var n *bgp.RouteTargetMembershipNLRI
				switch rnd.Intn(8) {
				case 0: // /0 default
					n = bgp.NewRouteTargetMembershipNLRI(0, nil)
				case 1: // /32 origin-as only
					n = bgp.NewRouteTargetMembershipNLRI(65001+uint32(rnd.Intn(2)), nil)
				case 2: // intermediate RFC 4684 depth (33..95); the
					// constructor only emits 0/32/96, so set Length the way
					// ParseRouteTargetMembershipNLRI does for a masked parse.
					// This keeps the RT bits below Length populated — the
					// config-parse shape, and the stricter unmasked-key case.
					// (Wire decode zeroes those bits in decodeFromBytes; both
					// shapes resolve through the same nlriToPrefix.)
					n = bgp.NewRouteTargetMembershipNLRI(65001+uint32(rnd.Intn(2)), mustRT(routeTargets[rnd.Intn(len(routeTargets))]))
					n.Length = uint8(33 + rnd.Intn(63))
				case 3: // RT whose trie key is unsupported: nlriToPrefix
					// yields an invalid prefix, PrefixCondition then returns
					// false under ANY and true under INVERT — pin that the
					// prover and the real walk agree on the asymmetry
					n = bgp.NewRouteTargetMembershipNLRI(65001+uint32(rnd.Intn(2)), bgp.NewOpaqueExtended(true, []byte{1, 2, 3, 4, 5, 6}))
				default: // /96 exact
					n = bgp.NewRouteTargetMembershipNLRI(65001+uint32(rnd.Intn(2)), mustRT(routeTargets[rnd.Intn(len(routeTargets))]))
				}
				nlri = n
				family = bgp.RF_RTC_UC
				mp, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_RTC_UC, []bgp.PathNLRI{{NLRI: n}}, netip.MustParseAddr("10.0.0.9"))
				if err != nil {
					t.Fatal(err)
				}
				attrs = append(attrs, mp)
			default: // IPv4-UC
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
				// Corpus diversity, not mutation-catching power: with the RT
				// natively present, ecs-conditioned statements can match in
				// the real walk and the trap's "add" action exercises the
				// attribute-merge path instead of always constructing the
				// attribute. (The trap's catches come from paths LACKING the
				// RT — pre/post-clone evaluation agrees when it is native.)
				attrs = append(attrs, bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{mustRT("65000:100")}))
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
			if family == bgp.RF_RTC_UC {
				totalRtc++
				// R-258 reach witness: in an rtc-first iteration with an
				// assigned id, the prover's walk evaluated the leading
				// psrtc statement on this RTC path BY CONSTRUCTION (first
				// statement of the first policy, whitelisted-only). raw is
				// the trie outcome that evaluation computed; the statement
				// applies rtcFirstInvert on top of it. Proven-reject counts
				// alone cannot witness reach — an RTC path is trivially
				// proven via default-reject or a neighbor match without
				// ever touching the RTC branch.
				if rtcFirst && assigned {
					raw := (&PrefixCondition{set: psrtc}).Evaluate(p, options) // option zero value = ANY
					if raw {
						rtcReachHit++
					} else {
						rtcReachMiss++
					}
					// The leading statement's condition, reconstructed with
					// its ACTUAL option: INVERT is not `!raw` — Evaluate's
					// invalid-trie-key early return (an RT ExtCommRouteTargetKey
					// cannot key, e.g. the OpaqueExtended leg) yields false
					// under BOTH options, because inversion applies only
					// after the trie stage.
					opt := MATCH_OPTION_ANY
					if rtcFirstInvert {
						opt = MATCH_OPTION_INVERT
					}
					stmtMatch := (&PrefixCondition{set: psrtc, option: opt}).Evaluate(p, options)
					// Behavioral pin: a matching leading statement decides
					// the walk at the RTC branch. Terminal reject must be
					// provable; terminal accept must not be.
					if stmtMatch {
						switch rtcFirstDisp {
						case oc.ROUTE_DISPOSITION_REJECT_ROUTE:
							if !pr {
								t.Errorf("iter %d sample %d: leading rtc-prefix reject not proven", iter, k)
							} else {
								provenViaRtcPrefix++
							}
						case oc.ROUTE_DISPOSITION_ACCEPT_ROUTE:
							if pr {
								t.Errorf("iter %d sample %d: proof claimed past a matching rtc-prefix accept", iter, k)
							} else {
								acceptPinViaRtcPrefix++
							}
						}
					}
				}
			}
			cloned := UpdatePathAttrs(logger, gConf, peerInfo, p)
			real := r.ApplyPolicy(id, POLICY_DIRECTION_EXPORT, cloned, options)
			if pr {
				proven++
				if family == bgp.RF_RTC_UC {
					provenRtc++
				}
				if real != nil {
					t.Errorf("iter %d sample %d: prover said REJECT but ApplyPolicy accepted: %s", iter, k, real)
				}
			}
		}
	}
	t.Logf("total=%d proven=%d totalRtc=%d provenRtc=%d rtcReachHit=%d rtcReachMiss=%d provenViaRtcPrefix=%d acceptPinViaRtcPrefix=%d",
		total, proven, totalRtc, provenRtc, rtcReachHit, rtcReachMiss, provenViaRtcPrefix, acceptPinViaRtcPrefix)
	if proven == 0 {
		t.Fatal("prover never fired; test is vacuous")
	}
	// Floors are well under the seeded run's observed counts (deterministic
	// by construction) but far enough from zero to catch the corpus
	// degenerating into single-digit accidental coverage. rtcReachHit/Miss
	// are computed test-side and witness corpus SHAPE (the RTC trie resolves
	// both ways on prover-walked statements); the prover linkage itself is
	// carried by the provenViaRtcPrefix/acceptPinViaRtcPrefix pins.
	if rtcReachHit < 200 || rtcReachMiss < 200 {
		t.Fatalf("RTC trie-match coverage on rtc-first samples degenerated: hit=%d miss=%d (want >=200 each; Bendrr R-258)", rtcReachHit, rtcReachMiss)
	}
	if provenViaRtcPrefix < 50 || acceptPinViaRtcPrefix < 50 {
		t.Fatalf("too few walks decided at the RTC prefix branch: reject-pins=%d accept-pins=%d (want >=50 each; Bendrr R-258)", provenViaRtcPrefix, acceptPinViaRtcPrefix)
	}
	if provenRtc < 200 {
		t.Fatalf("too few proven rejects on RTC paths: %d (want >=200)", provenRtc)
	}
}
