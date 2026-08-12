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
	"sync"
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

// installRigScopedExportGate installs the byte-faithful rig-rendered gate
// on shared, exactly as ConfigureExportGate sends it:
//
//   - defined sets (export.go:355-450: single-address prefix form for
//     neighbors; masked prefixes with min=bits / max=32 for the widened
//     scope), fed through the fork's OWN AddDefinedSet conversion;
//   - policies, exactly as desiredGatePolicies (export.go:154-183) and
//     scopedExportPolicy (export.go:193-223) render them, fed through the
//     fork's OWN AddPolicy conversion;
//   - wire-test/active assignment order and fail-closed default
//     (export.go:884-886, 974-984).
func installRigScopedExportGate(tb testing.TB, shared *table.RoutingPolicy) {
	tb.Helper()
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
		require.NoError(tb, err)
		require.NoError(tb, shared.AddDefinedSet(set, false))
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
		require.NoError(tb, err)
		require.NoError(tb, shared.AddPolicy(p, false))
	}

	require.NoError(tb, shared.AddPolicyAssignment(table.GLOBAL_RIB_NAME, table.POLICY_DIRECTION_EXPORT,
		[]*oc.PolicyDefinition{
			{Name: "bendrr-export-gate-guard"},
			{Name: "bendrr-export-scope"},
			{Name: "bendrr-export-gate-allow"},
		},
		table.ROUTE_TYPE_REJECT))
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

	installRigScopedExportGate(t, shared)

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

// TestSyncRankedAddPathSetHoistedSkipRigShape (Bendrr R-230 phase-3) pins
// the prover-based reject skip hoisted ABOVE the per-update ADD-PATH
// ranked-set sync bookkeeping, on the same byte-faithful rig-rendered gate
// shape:
//
//   - a non-canary restore announce toward the probe peer performs NO
//     destination lookup and NO known-path-list evaluation: the nil-rib
//     call nil-panics inside GetDestination if the skip regresses, and a
//     stable filterpathEntries pins that the sync loop never ran (counter
//     seams only — test-only observability, the documented stance at
//     prePolicyFilterpath);
//   - the exact canary /24 still syncs and announces through the full
//     bookkeeping (the nightly latency probe's accepted leg);
//   - the accepting inventory router runs the full loop, paying only the
//     hoisted dry-run;
//   - a VRF-attached peer falls through entirely — the prover would
//     dry-run the global NLRI space while the real walk evaluates the
//     ToLocal rewrite (the same keying trap as the phase-1 site's
//     lookupPath note).
func TestSyncRankedAddPathSetHoistedSkipRigShape(t *testing.T) {
	rib := table.NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC})
	src := newPeerandInfo(t, 1, 2, "10.0.0.7", rib)
	probe := newPeerandInfo(t, 1, 3, "127.0.1.1", rib)
	router := newPeerandInfo(t, 1, 3, "10.0.0.2", rib)

	shared := table.NewRoutingPolicy(logger)
	require.NoError(t, shared.Reset(&oc.RoutingPolicy{}, nil))
	probe.policy = shared
	router.policy = shared
	installRigScopedExportGate(t, shared)

	// Send-only ADD-PATH toward the probe (bendrr rig/procs.go:344-354);
	// the router gets the same mode so both legs exercise the wrapper.
	for _, p := range []*peer{probe, router} {
		p.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{
			bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_SEND,
		})
	}

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

	// The non-canary destination EXISTS in the table, so the empty result
	// below comes from the hoisted skip, not from a dest==nil early out.
	nonCanary := mk("100.64.12.0/24")
	rib.Update(nonCanary)

	skipsBefore := s.precloneSyncSkips.Load()
	entriesBefore := s.filterpathEntries.Load()
	assert.Empty(t, s.syncRankedAddPathSet(rib, probe, bgp.RF_IPv4_UC, nonCanary, ""),
		"probe non-canary announce must sync to nothing")
	assert.Equal(t, skipsBefore+1, s.precloneSyncSkips.Load(),
		"the hoisted skip must fire on the rig-rendered (masklength-range) shape")
	assert.Equal(t, entriesBefore, s.filterpathEntries.Load(),
		"the hoisted skip must not run the sync loop (no per-path filterpath)")
	assert.False(t, probe.hasPathAlreadyBeenSent(nonCanary))
	assert.False(t, probe.isPathSendMaxFiltered(nonCanary),
		"the skipped sync must leave no send-max bookkeeping behind")

	// Hard no-lookup seam: with a nil table manager, any destination
	// lookup nil-panics — returning cleanly proves the skip decides
	// BEFORE GetDestination.
	assert.Empty(t, s.syncRankedAddPathSet(nil, probe, bgp.RF_IPv4_UC, nonCanary, ""))
	assert.Equal(t, skipsBefore+2, s.precloneSyncSkips.Load())

	// Exact canary /24: never provable, full bookkeeping, announced.
	canary := mk("198.18.3.0/24")
	rib.Update(canary)
	got := s.syncRankedAddPathSet(rib, probe, bgp.RF_IPv4_UC, canary, "")
	require.Len(t, got, 1, "ROUTE LOSS: exact canary /24 must still sync and announce to the probe peer")
	assert.False(t, got[0].IsWithdraw)
	assert.Equal(t, canary.GetLocalKey(), got[0].GetLocalKey())
	probe.updateRoutes(got...) // as the propagateUpdateToNeighbors call site does
	assert.True(t, probe.hasPathAlreadyBeenSent(canary))
	assert.Equal(t, skipsBefore+2, s.precloneSyncSkips.Load(),
		"the accepted canary must not tick the sync-skip counter")

	// Inventory router: scope statements miss on neighbor, the trailing
	// allow accepts — not provable, the full loop runs and announces.
	entriesBefore = s.filterpathEntries.Load()
	got = s.syncRankedAddPathSet(rib, router, bgp.RF_IPv4_UC, nonCanary, "")
	require.Len(t, got, 1, "ROUTE LOSS: inventory router must keep the full export")
	assert.Greater(t, s.filterpathEntries.Load(), entriesBefore,
		"the router leg must run the real sync loop")
	assert.Equal(t, skipsBefore+2, s.precloneSyncSkips.Load())

	// VRF-attached peer: must fall through the gate (no skip tick) even
	// though the assignment provably rejects in the GLOBAL NLRI space.
	vrfPeer := newPeerandInfo(t, 1, 3, "127.0.2.1", rib)
	vrfPeer.policy = shared
	vrfPeer.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{
		bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_SEND,
	})
	vrfPeer.fsm.lock.Lock()
	vrfConf := vrfPeer.fsm.pConf.ReadCopy()
	vrfConf.Config.Vrf = "vrf-red"
	vrfPeer.fsm.pConf.Update(&vrfConf)
	vrfPeer.fsm.lock.Unlock()
	assert.Empty(t, s.syncRankedAddPathSet(rib, vrfPeer, bgp.RF_IPv4_UC, nonCanary, "vrf-red"))
	assert.Equal(t, skipsBefore+2, s.precloneSyncSkips.Load(),
		"VRF peers must not engage the hoisted skip (ToLocal keys a different NLRI space)")
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
	// The fixture builders take the *testing.B directly (review round 1,
	// minor-9): the earlier zero-value &testing.T{} stand-in swallowed
	// assertion failures silently.
	ribSrc := table.NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC})
	src := newPeerandInfo(b, 1, 2, "10.0.0.7", ribSrc)
	ribProbe := table.NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC})
	probe := newPeerandInfo(b, 1, 3, "127.0.1.1", ribProbe)
	ribRouter := table.NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC})
	router := newPeerandInfo(b, 1, 3, "10.0.0.2", ribRouter)

	shared := table.NewRoutingPolicy(logger)
	if err := shared.Reset(&oc.RoutingPolicy{}, nil); err != nil {
		b.Fatal(err)
	}
	probe.policy = shared
	router.policy = shared

	installRigScopedExportGate(b, shared)

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
	// (syncRankedAddPathSet -> syncRankedAddPathSetFromList):
	// per-update destination bookkeeping AROUND the skipped filterpath.
	known := []*table.Path{path}
	b.Run("probe-rejected-skip-addpath-sync-unit", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if got := s.syncRankedAddPathSetFromList(probe, bgp.RF_IPv4_UC, known, nil, true); len(got) != 0 {
				b.Fatal("expected no announcements")
			}
		}
	})

	// R-230 phase-3 units: the syncRankedAddPathSet WRAPPER against a
	// populated table, so GetDestination pays a realistic lookup (the rig
	// runs ~12M destinations; this rib holds 200k — the lookup is a per-
	// family map+trie, so the unit delta understates the rig only through
	// cache effects). "presync-bookkeeping" reconstructs the pre-phase-3
	// wrapper body byte-for-byte (GetDestination + GetKnownPathList +
	// FromList, per-path short-circuit armed as it was then);
	// "hoisted-skip" is the shipped wrapper, which now proves the reject
	// before any of it.
	rib, syncPath := precloneBenchTable()

	oldSyncBody := func(peer *peer, newPath *table.Path) []*table.Path {
		dest := rib.GetDestination(newPath)
		if dest == nil {
			return nil
		}
		newLocalKey := newPath.GetLocalKey()
		return s.syncRankedAddPathSetFromList(peer, bgp.RF_IPv4_UC, dest.GetKnownPathList(peer.TableID(), peer.AS()), &newLocalKey, true)
	}

	b.Run("probe-rejected-presync-bookkeeping-unit", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if got := oldSyncBody(probe, syncPath); len(got) != 0 {
				b.Fatal("expected no announcements")
			}
		}
	})
	b.Run("probe-rejected-hoisted-skip-sync-unit", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if got := s.syncRankedAddPathSet(rib, probe, bgp.RF_IPv4_UC, syncPath, ""); len(got) != 0 {
				b.Fatal("expected no announcements")
			}
		}
	})
	// Accepted leg: the hoisted prover dry-run is added cost for the
	// inventory router (it walks to the allow and returns false), but the
	// loop's per-path dry-runs are disarmed in exchange (MAJOR-5 option
	// (a)). new-vs-old delta = the constraint-5 overhead after threading.
	b.Run("router-accepted-presync-bookkeeping-unit", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if got := oldSyncBody(router, syncPath); len(got) == 0 {
				b.Fatal("expected an announcement")
			}
		}
	})
	b.Run("router-accepted-hoisted-sync-unit", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if got := s.syncRankedAddPathSet(rib, router, bgp.RF_IPv4_UC, syncPath, ""); len(got) == 0 {
				b.Fatal("expected an announcement")
			}
		}
	})
}

// precloneBenchTable lazily builds the 200k-destination benchmark table
// and the probe announce injected into it, ONCE per test binary (review
// round 1, minor-10: the parent benchmark body re-runs per -count and per
// sub-benchmark targeting, and rebuilding 200k destinations each time
// dominated wall time). Benchmark runs only read the table, so sharing it
// across invocations is safe; the injected path is returned so the
// reannounce-key leg keys on the exact stored object.
var precloneBenchTable = sync.OnceValues(func() (*table.TableManager, *table.Path) {
	rib := table.NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC})
	src := &table.PeerInfo{
		AS: 2, LocalAS: 1,
		Address:      netip.MustParseAddr("10.0.0.7"),
		ID:           netip.MustParseAddr("10.0.0.7"),
		LocalAddress: netip.MustParseAddr("1.1.1.1"),
		LocalID:      netip.MustParseAddr("1.1.1.1"),
	}
	mk := func(prefix string) *table.Path {
		nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
		if err != nil {
			panic(err)
		}
		nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.9"))
		if err != nil {
			panic(err)
		}
		return table.NewPath(bgp.RF_IPv4_UC, src, bgp.PathNLRI{NLRI: nlri}, false, []bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(0),
			bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{2})}),
			nh,
		}, time.Now(), false)
	}
	for i := 0; i < 200_000; i++ {
		rib.Update(mk(fmt.Sprintf("100.%d.%d.%d/32", 65+i/(256*256), i/256%256, i%256)))
	}
	path := mk("100.64.12.0/24")
	rib.Update(path)
	return rib, path
})
