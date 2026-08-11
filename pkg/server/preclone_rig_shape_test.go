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

// TestFilterpathPrecloneRigScopedExportShape (Bendrr R-230 phase-2
// residual triage, 2026-08-11): a byte-faithful reconstruction of the
// scoped-export gate the rig ACTUALLY renders as of bendrr main —
// including the 2026-08-07 (bendrr 4bc8339) per-prefix mask-length
// ranges with the /16 fail-closed floor — installed through the same
// API-struct conversion path the live AddDefinedSet/AddPolicy handlers
// run. It answers one question: does ProvablyRejectsPreClone's condition
// whitelist handle the masklength-range prefix-condition form, i.e. does
// the phase-2 short-circuit fire on the rig's policy shape?
//
// The earlier gate-chain tests (TestFilterpathPrecloneRejectShortCircuit,
// TestFilterpathPrecloneSharedGlobalAssignment here, and
// buildBendrrGateChain in internal/pkg/table/policy_preclone_test.go)
// model the canary set WITHOUT mask-length ranges — the pre-4bc8339
// shape — so none of them witnesses the range form end to end.
//
// Mirrored sources (bendrr repo, main):
//   - pkg/gobgp/export.go:130-149  gateStatement (content-hashed names)
//   - pkg/gobgp/export.go:154-183  desiredGatePolicies (guard INVERT
//     reject / allow ANY accept over "bendrr-router-neighbors")
//   - pkg/gobgp/export.go:193-223  scopedExportPolicy (accept scoped
//     neighbor AND scope prefix; reject scoped neighbor)
//   - pkg/gobgp/export.go:437-448  prefix entries MaskLengthMin=bits,
//     MaskLengthMax=32 under IncludeMoreSpecifics
//   - pkg/gobgp/export.go:884-886,974-984  assignment guard->scope->allow,
//     DefaultAction REJECT
//   - rig/procs.go:414-418  the rig always passes
//     -export-scope-more-specifics with the scope (so every rendered
//     entry carries a widened range)
//   - rig/wireprobe.go:81-110,134-140  CanaryCarve (the 128 /24s of
//     198.18.0.0/15 whose v4 universe index is ≡3 mod 4) and BenchCarve
//     (240.0.0.0/16 .. 240.7.0.0/16)
//
// Fork install path exercised: newDefinedSetFromApiStruct ->
// newPrefixFromApiStruct (grpc_server.go — the exact conversion the
// AddDefinedSet handler runs, carrying MaskLengthMin/Max into
// table.Prefix.MasklengthRange*) and newPolicyFromApiStruct (the
// AddPolicy handler's conversion).

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// rigGateStatement replicates bendrr pkg/gobgp/export.go gateStatement
// (lines 130-149) verbatim: the statement name is base + first 4 bytes of
// the sha256 of a hand-rolled canonical string over exactly the fields
// the gate sets, with the prefix-set clause appended only when present.
func rigGateStatement(base string, conds *api.Conditions, actions *api.Actions) *api.Statement {
	canon := fmt.Sprintf("v1|%s|neighbor_set=%s|match_type=%d|route_action=%d",
		base,
		conds.GetNeighborSet().GetName(),
		int32(conds.GetNeighborSet().GetType()),
		int32(actions.GetRouteAction()))
	if ps := conds.GetPrefixSet(); ps != nil {
		canon += fmt.Sprintf("|prefix_set=%s|prefix_match_type=%d", ps.GetName(), int32(ps.GetType()))
	}
	sum := sha256.Sum256([]byte(canon))
	return &api.Statement{
		Name:       base + "-" + hex.EncodeToString(sum[:4]),
		Conditions: conds,
		Actions:    actions,
	}
}

// rigScopePrefixes renders the scope prefix-set content exactly as
// ConfigureExportGate does for the rig's carves (export.go:437-448 with
// IncludeMoreSpecifics=true): CanaryCarve's 128 /24s as 24..32 and
// BenchCarve's 8 /16s as 16..32.
func rigScopePrefixes() []*api.Prefix {
	out := make([]*api.Prefix, 0, 136)
	// CanaryCarve (rig/wireprobe.go:99-110): scanning 198.18.0.0/15, keep
	// the /24s whose v4 universe index (a-1)*65536+b*256+c is ≡3 mod 4.
	for b := 18; b <= 19; b++ {
		for c := 0; c <= 255; c++ {
			if ((198-1)*65536+b*256+c)%4 != 3 {
				continue
			}
			out = append(out, &api.Prefix{
				IpPrefix:      fmt.Sprintf("198.%d.%d.0/24", b, c),
				MaskLengthMin: 24,
				MaskLengthMax: 32,
			})
		}
	}
	// BenchCarve (rig/wireprobe.go:134-140): 240.0.0.0/16 .. 240.7.0.0/16.
	for i := 0; i < 8; i++ {
		out = append(out, &api.Prefix{
			IpPrefix:      fmt.Sprintf("240.%d.0.0/16", i),
			MaskLengthMin: 16,
			MaskLengthMax: 32,
		})
	}
	return out
}

func TestFilterpathPrecloneRigScopedExportShape(t *testing.T) {
	// Session shape: one source peer, one probe peer (rig convention:
	// 127/8 loopback), one inventory router, plus an out-of-inventory
	// stranger for the guard leg. Probe and router share ONE
	// RoutingPolicy under GLOBAL_RIB_NAME — the production topology (the
	// gate rides the global export assignment; bendrr export.go:65-67).
	ribSrc := table.NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC})
	src := newPeerandInfo(t, 1, 2, "10.0.0.7", ribSrc)
	ribProbe := table.NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC})
	probe := newPeerandInfo(t, 1, 3, "127.0.1.1", ribProbe)
	ribRouter := table.NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC})
	router := newPeerandInfo(t, 1, 3, "10.0.0.2", ribRouter)
	ribStranger := table.NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC})
	stranger := newPeerandInfo(t, 1, 3, "10.9.9.9", ribStranger)

	shared := table.NewRoutingPolicy(logger)
	require.NoError(t, shared.Reset(&oc.RoutingPolicy{}, nil))
	probe.policy = shared
	router.policy = shared
	stranger.policy = shared
	require.Equal(t, table.GLOBAL_RIB_NAME, probe.TableID())

	// Defined sets, exactly as ConfigureExportGate sends them
	// (export.go:355-450: single-address prefix form for neighbors;
	// masked prefixes with min=bits / max=32 for the widened scope), fed
	// through the fork's OWN AddDefinedSet conversion.
	for _, ds := range []*api.DefinedSet{
		{
			DefinedType: api.DefinedType_DEFINED_TYPE_NEIGHBOR,
			Name:        "bendrr-router-neighbors",
			List:        []string{"10.0.0.2/32", "127.0.1.1/32"},
		},
		{
			DefinedType: api.DefinedType_DEFINED_TYPE_NEIGHBOR,
			Name:        "bendrr-export-scope-neighbors",
			List:        []string{"127.0.1.1/32"},
		},
		{
			DefinedType: api.DefinedType_DEFINED_TYPE_PREFIX,
			Name:        "bendrr-export-scope-prefixes",
			Prefixes:    rigScopePrefixes(),
		},
	} {
		set, err := newDefinedSetFromApiStruct(ds)
		require.NoError(t, err)
		require.NoError(t, shared.AddDefinedSet(set, false))
	}

	// Policies, exactly as desiredGatePolicies (export.go:154-183) and
	// scopedExportPolicy (export.go:193-223) render them, fed through the
	// fork's OWN AddPolicy conversion.
	for _, pol := range []*api.Policy{
		{
			Name: "bendrr-export-gate-guard",
			Statements: []*api.Statement{rigGateStatement(
				"bendrr-export-gate-reject-unknown",
				&api.Conditions{NeighborSet: &api.MatchSet{
					Type: api.MatchSet_TYPE_INVERT, Name: "bendrr-router-neighbors",
				}},
				&api.Actions{RouteAction: api.RouteAction_ROUTE_ACTION_REJECT},
			)},
		},
		{
			Name: "bendrr-export-scope",
			Statements: []*api.Statement{
				rigGateStatement(
					"bendrr-export-scope-accept",
					&api.Conditions{
						NeighborSet: &api.MatchSet{Type: api.MatchSet_TYPE_ANY, Name: "bendrr-export-scope-neighbors"},
						PrefixSet:   &api.MatchSet{Type: api.MatchSet_TYPE_ANY, Name: "bendrr-export-scope-prefixes"},
					},
					&api.Actions{RouteAction: api.RouteAction_ROUTE_ACTION_ACCEPT},
				),
				rigGateStatement(
					"bendrr-export-scope-reject",
					&api.Conditions{
						NeighborSet: &api.MatchSet{Type: api.MatchSet_TYPE_ANY, Name: "bendrr-export-scope-neighbors"},
					},
					&api.Actions{RouteAction: api.RouteAction_ROUTE_ACTION_REJECT},
				),
			},
		},
		{
			Name: "bendrr-export-gate-allow",
			Statements: []*api.Statement{rigGateStatement(
				"bendrr-export-gate-allow-routers",
				&api.Conditions{NeighborSet: &api.MatchSet{
					Type: api.MatchSet_TYPE_ANY, Name: "bendrr-router-neighbors",
				}},
				&api.Actions{RouteAction: api.RouteAction_ROUTE_ACTION_ACCEPT},
			)},
		},
	} {
		p, err := newPolicyFromApiStruct(pol)
		require.NoError(t, err)
		require.NoError(t, shared.AddPolicy(p, false))
	}

	// Wire-test/active assignment order and fail-closed default
	// (export.go:884-886, 974-984).
	require.NoError(t, shared.AddPolicyAssignment(table.GLOBAL_RIB_NAME, table.POLICY_DIRECTION_EXPORT,
		[]*oc.PolicyDefinition{
			{Name: "bendrr-export-gate-guard"},
			{Name: "bendrr-export-scope"},
			{Name: "bendrr-export-gate-allow"},
		},
		table.ROUTE_TYPE_REJECT))

	s := NewBgpServer()
	mk := func(prefix string) *table.Path {
		nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
		require.NoError(t, err)
		nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.9"))
		require.NoError(t, err)
		pa := []bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(0),
			bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{2})}),
			nh,
		}
		return table.NewPath(bgp.RF_IPv4_UC, src.peerInfo.Load(), bgp.PathNLRI{NLRI: nlri}, false, pa, time.Now(), false)
	}

	// (1) THE VERDICT CASE: a LoadGen-shaped non-canary announce toward
	// the probe peer. The soak's ~12M paths/cycle are this population; if
	// the masklength-range form made the prover bail, this would return
	// the path via the full pipeline with no counter tick.
	before := s.precloneRejectSkips.Load()
	assert.Nil(t, s.filterpath(probe, mk("100.64.12.0/24"), nil))
	assert.Equal(t, before+1, s.precloneRejectSkips.Load(),
		"probe non-canary reject must engage the pre-clone short-circuit on the rig-rendered (masklength-range) shape")

	// (2) A load-side /24 INSIDE 198.18.0.0/15 but outside the reserved
	// residue class (index ≡0 mod 4): sits between carve entries in the
	// trie, still provably rejected.
	assert.Nil(t, s.filterpath(probe, mk("198.18.0.0/24"), nil))
	assert.Equal(t, before+2, s.precloneRejectSkips.Load(),
		"non-reserved 198.18/15 sibling must still be a provable reject")

	// (3) Exact canary /24 (198.18.3.0/24 is index ≡3 mod 4): accepted by
	// the scope statement — never provable, no skip, path exported.
	got := s.filterpath(probe, mk("198.18.3.0/24"), nil)
	require.NotNil(t, got, "ROUTE LOSS: exact canary /24 must export to the probe peer")
	assert.Equal(t, before+2, s.precloneRejectSkips.Load())

	// (4) The 4bc8339 widening itself: a /32 UNDER a canary /24 is inside
	// the 24..32 range — accepted (rr-bench's legacy-residue retraction
	// leg), so no skip.
	got = s.filterpath(probe, mk("198.18.3.7/32"), nil)
	require.NotNil(t, got, "ROUTE LOSS: /32 under a canary /24 must export (24..32 widening)")
	assert.Equal(t, before+2, s.precloneRejectSkips.Load())

	// (5) A bench-burst /32 under a class E /16 is inside the 16..32
	// range — accepted, no skip.
	got = s.filterpath(probe, mk("240.3.7.9/32"), nil)
	require.NotNil(t, got, "ROUTE LOSS: /32 under a bench /16 must export (16..32 widening)")
	assert.Equal(t, before+2, s.precloneRejectSkips.Load())

	// (6) Shorter than the range floor: a /8 covering the bench /16s has
	// masklen 8 < MaskLengthMin 16 and no supernet entry — misses the
	// accept statement, provably rejected.
	assert.Nil(t, s.filterpath(probe, mk("240.0.0.0/8"), nil))
	assert.Equal(t, before+3, s.precloneRejectSkips.Load(),
		"a covering prefix shorter than the range floor must be a provable reject")

	// (7) Inventory router: scope statements miss on neighbor, the
	// trailing allow accepts — not provable, full export unchanged.
	got = s.filterpath(router, mk("100.64.12.0/24"), nil)
	require.NotNil(t, got, "ROUTE LOSS: inventory router must keep the full export")
	assert.Equal(t, before+3, s.precloneRejectSkips.Load())

	// (8) Out-of-inventory neighbor: the guard's INVERT match terminally
	// rejects — provable, skip fires (R-105 fail-closed leg).
	assert.Nil(t, s.filterpath(stranger, mk("100.64.12.0/24"), nil))
	assert.Equal(t, before+4, s.precloneRejectSkips.Load(),
		"guard reject toward an unknown neighbor must be provable")

	// (9) Withdraws are never provable (ApplyPolicy passes them through);
	// the phase-1 suppression owns that leg, the counter must not move.
	assert.Nil(t, s.filterpath(probe, mk("100.64.12.0/24").Clone(true), nil))
	assert.Equal(t, before+4, s.precloneRejectSkips.Load(),
		"withdraw leg must not engage the announce-leg short-circuit")
}

// BenchmarkPrecloneRigShapeResidual measures what a probe peer's announce
// leg still costs PER PATH with the phase-2 short-circuit firing, on the
// exact rig-rendered gate shape. BenchmarkPrecloneGateChain (table pkg)
// measures the bare prover (~45ns); this measures the whole
// s.filterpath unit the fan-out loop actually pays per (path, peer) —
// prePolicyFilterpath's per-path PolicyOptions allocation and setup
// happen BEFORE the skip check (server.go prePolicyFilterpath), and for
// ADD-PATH send peers (the rig's probe sessions — bendrr
// rig/procs.go:344-354 "Send-only ADD-PATH toward the probe") the
// per-update syncRankedAddPathSet bookkeeping around it is not skipped
// either. Context for the R-230 phase-2 residual triage: the withdraw
// leg's phase-1 fast skip is a hasPathAlreadyBeenSent map lookup before
// any of this, which is consistent with the rig reading (withdraw
// parity, restore-only ~2x adder).
func BenchmarkPrecloneRigShapeResidual(b *testing.B) {
	t := &testing.T{}
	ribSrc := table.NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC})
	src := newPeerandInfo(t, 1, 2, "10.0.0.7", ribSrc)
	ribProbe := table.NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC})
	probe := newPeerandInfo(t, 1, 3, "127.0.1.1", ribProbe)
	ribRouter := table.NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC})
	router := newPeerandInfo(t, 1, 3, "10.0.0.2", ribRouter)

	shared := table.NewRoutingPolicy(logger)
	if err := shared.Reset(&oc.RoutingPolicy{}, nil); err != nil {
		b.Fatal(err)
	}
	probe.policy = shared
	router.policy = shared

	for _, ds := range []*api.DefinedSet{
		{
			DefinedType: api.DefinedType_DEFINED_TYPE_NEIGHBOR,
			Name:        "bendrr-router-neighbors",
			List:        []string{"10.0.0.2/32", "127.0.1.1/32"},
		},
		{
			DefinedType: api.DefinedType_DEFINED_TYPE_NEIGHBOR,
			Name:        "bendrr-export-scope-neighbors",
			List:        []string{"127.0.1.1/32"},
		},
		{
			DefinedType: api.DefinedType_DEFINED_TYPE_PREFIX,
			Name:        "bendrr-export-scope-prefixes",
			Prefixes:    rigScopePrefixes(),
		},
	} {
		set, err := newDefinedSetFromApiStruct(ds)
		if err != nil {
			b.Fatal(err)
		}
		if err := shared.AddDefinedSet(set, false); err != nil {
			b.Fatal(err)
		}
	}
	for _, pol := range []*api.Policy{
		{
			Name: "bendrr-export-gate-guard",
			Statements: []*api.Statement{rigGateStatement(
				"bendrr-export-gate-reject-unknown",
				&api.Conditions{NeighborSet: &api.MatchSet{
					Type: api.MatchSet_TYPE_INVERT, Name: "bendrr-router-neighbors",
				}},
				&api.Actions{RouteAction: api.RouteAction_ROUTE_ACTION_REJECT},
			)},
		},
		{
			Name: "bendrr-export-scope",
			Statements: []*api.Statement{
				rigGateStatement(
					"bendrr-export-scope-accept",
					&api.Conditions{
						NeighborSet: &api.MatchSet{Type: api.MatchSet_TYPE_ANY, Name: "bendrr-export-scope-neighbors"},
						PrefixSet:   &api.MatchSet{Type: api.MatchSet_TYPE_ANY, Name: "bendrr-export-scope-prefixes"},
					},
					&api.Actions{RouteAction: api.RouteAction_ROUTE_ACTION_ACCEPT},
				),
				rigGateStatement(
					"bendrr-export-scope-reject",
					&api.Conditions{
						NeighborSet: &api.MatchSet{Type: api.MatchSet_TYPE_ANY, Name: "bendrr-export-scope-neighbors"},
					},
					&api.Actions{RouteAction: api.RouteAction_ROUTE_ACTION_REJECT},
				),
			},
		},
		{
			Name: "bendrr-export-gate-allow",
			Statements: []*api.Statement{rigGateStatement(
				"bendrr-export-gate-allow-routers",
				&api.Conditions{NeighborSet: &api.MatchSet{
					Type: api.MatchSet_TYPE_ANY, Name: "bendrr-router-neighbors",
				}},
				&api.Actions{RouteAction: api.RouteAction_ROUTE_ACTION_ACCEPT},
			)},
		},
	} {
		p, err := newPolicyFromApiStruct(pol)
		if err != nil {
			b.Fatal(err)
		}
		if err := shared.AddPolicy(p, false); err != nil {
			b.Fatal(err)
		}
	}
	if err := shared.AddPolicyAssignment(table.GLOBAL_RIB_NAME, table.POLICY_DIRECTION_EXPORT,
		[]*oc.PolicyDefinition{
			{Name: "bendrr-export-gate-guard"},
			{Name: "bendrr-export-scope"},
			{Name: "bendrr-export-gate-allow"},
		},
		table.ROUTE_TYPE_REJECT); err != nil {
		b.Fatal(err)
	}

	s := NewBgpServer()
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("100.64.12.0/24"))
	if err != nil {
		b.Fatal(err)
	}
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.9"))
	if err != nil {
		b.Fatal(err)
	}
	pa := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{2})}),
		nh,
	}
	path := table.NewPath(bgp.RF_IPv4_UC, src.peerInfo.Load(), bgp.PathNLRI{NLRI: nlri}, false, pa, time.Now(), false)

	// The full per-(path, probe-peer) filterpath unit with the skip
	// firing: everything the announce fan-out still pays after phase-2.
	b.Run("probe-rejected-skip-filterpath-unit", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if s.filterpath(probe, path, nil) != nil {
				b.Fatal("expected a skipped reject")
			}
		}
	})
	// Same unit toward an accepting inventory router: the clone + full
	// walk baseline the skip is measured against.
	b.Run("router-accepted-full-pipeline", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if s.filterpath(router, path, nil) == nil {
				b.Fatal("expected an accept")
			}
		}
	})
	// The ADD-PATH announce-leg wrapper the probe sessions actually take
	// (server.go:1871 syncRankedAddPathSet -> syncRankedAddPathSetFromList):
	// per-update destination bookkeeping AROUND the skipped filterpath.
	known := []*table.Path{path}
	b.Run("probe-rejected-skip-addpath-sync-unit", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if got := s.syncRankedAddPathSetFromList(probe, bgp.RF_IPv4_UC, known, nil); len(got) != 0 {
				b.Fatal("expected no announcements")
			}
		}
	})
}
