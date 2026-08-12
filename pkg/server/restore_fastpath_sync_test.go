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

// Tests for the R-230 phase-3 hoisted sync skip (syncRankedAddPathSet):
// the scope-transition test drives the REAL announce fan-out
// (propagateUpdate -> propagateUpdateToNeighbors -> syncRankedAddPathSet)
// end to end, and the randomized differential pins the wrapper's
// wire-visible behavior and adv-state mutations against a byte-for-byte
// reconstruction of the pre-phase-3 wrapper body across randomized
// policies, paths, and mid-stream policy transitions.

import (
	"context"
	"fmt"
	"math/rand"
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

// enableAddPathSend flips the peer to send-only ADD-PATH for IPv4-UC with
// the given SendMax — the rig's probe-session shape (bendrr
// rig/procs.go:344-354).
func enableAddPathSend(t *testing.T, p *peer, sendMax uint8) {
	t.Helper()
	p.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{
		bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_SEND,
	})
	p.fsm.lock.Lock()
	conf := p.fsm.pConf.ReadCopy()
	found := false
	for i := range conf.AfiSafis {
		if conf.AfiSafis[i].State.Family != bgp.RF_IPv4_UC {
			continue
		}
		conf.AfiSafis[i].AddPaths.Config.SendMax = sendMax
		conf.AfiSafis[i].AddPaths.State.SendMax = sendMax
		found = true
	}
	p.fsm.pConf.Update(&conf)
	p.fsm.lock.Unlock()
	require.True(t, found)
}

// TestSyncRankedAddPathSetSkipScopeTransition (Bendrr R-230 phase-3,
// constraint: ADD-PATH transition safety) drives the real fan-out on the
// byte-faithful rig gate shape through a scope change in both directions:
//
//  1. a non-canary announce toward the probe peer engages the hoisted skip
//     (counter) and emits nothing;
//  2. the scope prefix-set is WIDENED to cover the prefix (the
//     scope-drift-repair re-render appends the same min=bits/max=32 form
//     ConfigureExportGate sends), and the next event on the destination
//     must announce BOTH the new path and the previously-skipped one — the
//     skip left no stale sync state, so the never-sent path promotes
//     cleanly;
//  3. the scope is NARROWED back and the next event engages the skip again
//     WITHOUT inventing withdraws for the now-unexportable sent paths (the
//     heal belongs to the policy-change soft reset, phase-2's
//     TestExportDumpPrecloneShortCircuitDuringDump pins that leg);
//  4. (review round 1, MAJOR-3) the policy ASSIGNMENT is rebound wholesale
//     to a bare reject-all — the drift-repair leg: SetPolicyAssignment
//     swaps Assignment.exportPolicies, a different path through getPolicy
//     than the defined-set mutations above — and the next event must
//     engage the skip on the new assignment;
//  5. the assignment is rebound BACK to the gate chain (scope re-widened),
//     and the next event must announce the new path and promote every path
//     skipped under reject-all — no stale sync state from the rebind;
//  6. the assignment is rebound to reject-all AGAIN while the scope stays
//     widened: the skip must re-engage on the assignment alone, inventing
//     no withdraws and leaving sent-state untouched.
func TestSyncRankedAddPathSetSkipScopeTransition(t *testing.T) {
	s := newExportDumpTestServer(t)
	t.Cleanup(func() {
		require.NoError(t, s.StopBgp(context.Background(), &api.StopBgpRequest{}))
		s.bfdServer.Stop()
	})

	// Probe peer at the rig's scope-neighbor address, send-only ADD-PATH,
	// SendMax wide enough that every accepted path across all six steps
	// fits (the selection cut is not what this test is about).
	p := addExportDumpTestPeer(t, s, "127.0.1.1", false)
	enableAddPathSend(t, p, 8)
	installRigScopedExportGate(t, s.policy)
	p.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)

	makeSourcePath := func(source string) *table.Path {
		t.Helper()
		nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("100.64.12.0/24"))
		require.NoError(t, err)
		nextHop, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.0.2.254"))
		require.NoError(t, err)
		sourceAddr := netip.MustParseAddr(source)
		return table.NewPath(bgp.RF_IPv4_UC, &table.PeerInfo{
			AS:           65010,
			ID:           sourceAddr,
			Address:      sourceAddr,
			LocalAS:      65001,
			LocalID:      netip.MustParseAddr("1.1.1.1"),
			LocalAddress: netip.MustParseAddr("1.1.1.1"),
		}, bgp.PathNLRI{NLRI: nlri}, false, []bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(0),
			bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
				bgp.NewAs4PathParam(2, []uint32{65010}),
			}),
			nextHop,
		}, time.Now(), false)
	}
	expectSilence := func(what string) {
		t.Helper()
		select {
		case o := <-p.fsm.outgoingCh.Out():
			t.Fatalf("%s reached the wire: %#v", what, o)
		case <-time.After(300 * time.Millisecond):
		}
	}
	drainAnnounces := func(n int) []*table.Path {
		t.Helper()
		var got []*table.Path
		deadline := time.After(5 * time.Second)
		for len(got) < n {
			select {
			case o := <-p.fsm.outgoingCh.Out():
				msg, ok := o.(*fsmOutgoingMsg)
				require.True(t, ok)
				got = append(got, msg.Paths...)
			case <-deadline:
				t.Fatalf("timed out waiting for %d announcements, got %d", n, len(got))
			}
		}
		return got
	}

	// (1) Rejected leg: the hoisted skip fires on the real fan-out and
	// nothing reaches the wire or the adv bookkeeping.
	pathA := makeSourcePath("10.0.0.2")
	skipsBefore := s.precloneSyncSkips.Load()
	s.propagateUpdate(nil, []*table.Path{pathA})
	expectSilence("hoisted-skip rejected announce")
	assert.Equal(t, skipsBefore+1, s.precloneSyncSkips.Load(),
		"the hoisted skip must fire through the real announce fan-out")
	assert.False(t, p.hasPathAlreadyBeenSent(pathA))

	// (2) Scope widens to cover the prefix (drift-repair re-render form).
	widen, err := newDefinedSetFromApiStruct(&api.DefinedSet{
		DefinedType: api.DefinedType_DEFINED_TYPE_PREFIX,
		Name:        "bendrr-export-scope-prefixes",
		Prefixes: []*api.Prefix{{
			IpPrefix:      "100.64.12.0/24",
			MaskLengthMin: 24,
			MaskLengthMax: 32,
		}},
	})
	require.NoError(t, err)
	require.NoError(t, s.policy.AddDefinedSet(widen, false)) // append, live set

	pathB := makeSourcePath("10.0.0.3")
	s.propagateUpdate(nil, []*table.Path{pathB})
	got := drainAnnounces(2)
	require.Len(t, got, 2,
		"post-widening event must announce the new path AND promote the previously-skipped one")
	seen := map[uint32]bool{}
	for _, path := range got {
		assert.False(t, path.IsWithdraw)
		assert.Equal(t, "100.64.12.0/24", path.GetPrefix())
		seen[path.LocalID()] = true
	}
	assert.True(t, seen[pathA.LocalID()], "previously-skipped path must promote (no stale sync state)")
	assert.True(t, seen[pathB.LocalID()])
	assert.True(t, p.hasPathAlreadyBeenSent(pathA))
	assert.True(t, p.hasPathAlreadyBeenSent(pathB))
	assert.Equal(t, skipsBefore+1, s.precloneSyncSkips.Load(),
		"the accepting event must not tick the sync-skip counter")

	// (3) Scope narrows back; the next event must skip again and must NOT
	// invent withdraws for the sent paths. NOTE (review round 1,
	// minor-11): this step asserts wire silence plus the counter tick
	// only — it does NOT establish byte parity with the unskipped sync
	// loop; parity is TestSyncRankedAddPathSetSkipDifferential's job.
	require.NoError(t, s.policy.DeleteDefinedSet(widen, false))
	pathC := makeSourcePath("10.0.0.4")
	s.propagateUpdate(nil, []*table.Path{pathC})
	expectSilence("post-narrowing event")
	assert.Equal(t, skipsBefore+2, s.precloneSyncSkips.Load(),
		"the hoisted skip must re-engage after the scope narrows")
	assert.True(t, p.hasPathAlreadyBeenSent(pathA), "sent-state must be untouched (heal is softresetOut's job)")
	assert.True(t, p.hasPathAlreadyBeenSent(pathB))
	assert.False(t, p.hasPathAlreadyBeenSent(pathC))

	// (4) Assignment rebind leg (review round 1, MAJOR-3): swap the
	// export assignment wholesale to a bare reject-all (no policies,
	// fail-closed default) — the shape bendrr's drift repair installs —
	// and drive the next event: the skip must fire on the REBOUND
	// assignment, silently and without touching state.
	gateChain := []*oc.PolicyDefinition{
		{Name: "bendrr-export-gate-guard"},
		{Name: "bendrr-export-scope"},
		{Name: "bendrr-export-gate-allow"},
	}
	require.NoError(t, s.policy.SetPolicyAssignment(table.GLOBAL_RIB_NAME, table.POLICY_DIRECTION_EXPORT,
		nil, table.ROUTE_TYPE_REJECT))
	pathD := makeSourcePath("10.0.0.5")
	s.propagateUpdate(nil, []*table.Path{pathD})
	expectSilence("post-rebind (reject-all) event")
	assert.Equal(t, skipsBefore+3, s.precloneSyncSkips.Load(),
		"the hoisted skip must fire on the wholesale-rebound reject-all assignment")
	assert.False(t, p.hasPathAlreadyBeenSent(pathD))

	// (5) Rebind BACK to the gate chain, scope re-widened to cover the
	// prefix: the next event must announce the new path AND promote the
	// paths skipped in steps 3-4 — the rebind left no stale sync state.
	require.NoError(t, s.policy.AddDefinedSet(widen, false))
	require.NoError(t, s.policy.SetPolicyAssignment(table.GLOBAL_RIB_NAME, table.POLICY_DIRECTION_EXPORT,
		gateChain, table.ROUTE_TYPE_REJECT))
	pathE := makeSourcePath("10.0.0.6")
	s.propagateUpdate(nil, []*table.Path{pathE})
	got = drainAnnounces(3)
	require.Len(t, got, 3,
		"post-rebind event must announce the new path and promote both rebind-skipped ones")
	seen = map[uint32]bool{}
	for _, path := range got {
		assert.False(t, path.IsWithdraw)
		seen[path.LocalID()] = true
	}
	assert.True(t, seen[pathC.LocalID()], "path skipped in step 3 must promote after the rebind")
	assert.True(t, seen[pathD.LocalID()], "path skipped under reject-all must promote after the rebind")
	assert.True(t, seen[pathE.LocalID()])
	assert.False(t, seen[pathA.LocalID()], "already-sent paths must not re-announce")
	assert.Equal(t, skipsBefore+3, s.precloneSyncSkips.Load())

	// (6) Rebind to reject-all AGAIN with the scope still widened: the
	// verdict must track the ASSIGNMENT, not the defined sets — skip,
	// silence, no withdraws, sent-state intact.
	require.NoError(t, s.policy.SetPolicyAssignment(table.GLOBAL_RIB_NAME, table.POLICY_DIRECTION_EXPORT,
		nil, table.ROUTE_TYPE_REJECT))
	pathF := makeSourcePath("10.0.0.8")
	s.propagateUpdate(nil, []*table.Path{pathF})
	expectSilence("second reject-all rebind event")
	assert.Equal(t, skipsBefore+4, s.precloneSyncSkips.Load(),
		"the hoisted skip must re-engage on the second rebind despite the widened scope")
	for _, sent := range []*table.Path{pathA, pathB, pathC, pathD, pathE} {
		assert.True(t, p.hasPathAlreadyBeenSent(sent), "rebind must leave sent-state untouched")
	}
	assert.False(t, p.hasPathAlreadyBeenSent(pathF))
}

// TestSyncRankedAddPathSetSkipDifferential (Bendrr R-230 phase-3) is the
// server-level companion of the phase-2 table-layer differential
// (TestProvablyRejectsPreCloneDifferential): across randomized policies
// (whitelisted prefix/neighbor conditions with masklength-range shapes,
// ANY and INVERT, non-whitelisted community conditions, all three
// dispositions, random or absent defaults) and randomized multi-path
// ADD-PATH destinations — with mid-stream prefix-set transitions in both
// directions — the shipped syncRankedAddPathSet must produce the same
// announcement sequence AND the same per-path adv-state mutations as a
// byte-for-byte reconstruction of the pre-phase-3 wrapper body, run on a
// twin peer that is indistinguishable to the policy engine.
//
// Review round 1, MAJOR-2 — two additions closing the corpus blind spot
// behind BLOCKER-1 (a valid-Address PeerInfo makes every path at a
// destination verdict-identical BY CONSTRUCTION, so no random draw could
// witness the NeighborCondition per-path source fallback):
//
//   - an INVALID-Address PeerInfo corpus dimension, with the neighbor set
//     pinned to a source-pool address so NeighborCondition's fallback to
//     path.GetSource().Address produces genuinely divergent per-path
//     verdicts at one destination (the reviewer's route-loss repro
//     class); destinations are also pre-seeded with never-synced paths,
//     so an unsound skip visibly suppresses their promotion; the old
//     body stays the oracle, and a coverage counter proves the
//     mixed-verdict shape actually occurred;
//   - a direct invariance property: whenever the hoisted gate's
//     preconditions hold, every known path at the destination must share
//     newPath's ProvablyRejectsPreClone verdict. ANY divergence is a
//     hazard — newPath is just one of the known paths, so divergence in
//     either direction means some announce order lets the skip blank a
//     live path — and a future whitelist addition that breaks
//     destination-invariance fails here even if the randomized announce
//     order never trips the output differential.
func TestSyncRankedAddPathSetSkipDifferential(t *testing.T) {
	rnd := rand.New(rand.NewSource(1))
	s := NewBgpServer()

	prefixPool := []string{
		"100.64.12.0/24", "100.64.13.0/24", "100.64.0.0/16",
		"198.18.3.0/24", "198.18.3.7/32", "240.3.0.0/16",
	}
	maskRanges := []string{"", "24..32", "16..32", "16..24"}
	neighborPool := []string{"127.0.9.9/32", "10.0.0.1/32", "0.0.0.0/0"}
	sourcePool := []string{"10.1.0.1", "10.1.0.2", "10.1.0.3"}

	pickMSO := func() oc.MatchSetOptionsRestrictedType {
		if rnd.Intn(4) == 0 {
			return oc.MATCH_SET_OPTIONS_RESTRICTED_TYPE_INVERT
		}
		return oc.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY
	}

	skipsBefore := s.precloneSyncSkips.Load()
	totalEvents, announced, mixedVerdictEvents := 0, 0, 0

	for iter := 0; iter < 300; iter++ {
		rib := table.NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC})
		// Twin peers, indistinguishable to the policy engine (same
		// address, AS, table id) but with independent adv state: pRef
		// runs the reconstructed pre-phase-3 body, pNew the shipped
		// wrapper.
		pRef := newPeerandInfo(t, 65001, 65002, "127.0.9.9", rib)
		pNew := newPeerandInfo(t, 65001, 65002, "127.0.9.9", rib)
		sendMax := uint8(rnd.Intn(3)) // 0 = uncapped
		enableAddPathSend(t, pRef, sendMax)
		enableAddPathSend(t, pNew, sendMax)

		// MAJOR-2(a) corpus dimension: an invalid-Address PeerInfo on
		// BOTH twins (they stay indistinguishable) flips
		// NeighborCondition onto its per-path GetSource().Address
		// fallback, so two known paths at one destination can earn
		// different policy verdicts — the hazard class BLOCKER-1's
		// IsValid gate exists for. The shipped wrapper must fall through
		// its hoisted skip here; the old body remains the oracle either
		// way.
		invalidInfo := rnd.Intn(4) == 0
		if invalidInfo {
			for _, twin := range []*peer{pRef, pNew} {
				info := *twin.peerInfo.Load()
				info.Address = netip.Addr{}
				twin.peerInfo.Store(&info)
			}
		}

		rp := table.NewRoutingPolicy(logger)
		require.NoError(t, rp.Reset(&oc.RoutingPolicy{}, nil))
		pRef.policy = rp
		pNew.policy = rp

		psPrefixes := []oc.Prefix{{
			IpPrefix:        netip.MustParsePrefix(prefixPool[rnd.Intn(len(prefixPool))]),
			MasklengthRange: maskRanges[rnd.Intn(len(maskRanges))],
		}}
		if rnd.Intn(2) == 0 {
			psPrefixes = append(psPrefixes, oc.Prefix{
				IpPrefix:        netip.MustParsePrefix(prefixPool[rnd.Intn(len(prefixPool))]),
				MasklengthRange: maskRanges[rnd.Intn(len(maskRanges))],
			})
		}
		ps, err := table.NewPrefixSet(oc.PrefixSet{PrefixSetName: "ps", PrefixList: psPrefixes})
		require.NoError(t, err)
		require.NoError(t, rp.AddDefinedSet(ps, false))
		// In the invalid-Info corpus the neighbor set is pinned to a
		// source-pool /32 so the per-path fallback verdicts genuinely
		// diverge across sources (matching one of the three, missing the
		// others); otherwise drawn at random as before.
		nsEntry := neighborPool[rnd.Intn(len(neighborPool))]
		if invalidInfo {
			nsEntry = "10.1.0.1/32"
		}
		ns, err := table.NewNeighborSet(oc.NeighborSet{
			NeighborSetName:  "ns",
			NeighborInfoList: []string{nsEntry},
		})
		require.NoError(t, err)
		require.NoError(t, rp.AddDefinedSet(ns, false))
		cs, err := table.NewCommunitySet(oc.CommunitySet{CommunitySetName: "cs", CommunityList: []string{"100:100"}})
		require.NoError(t, err)
		require.NoError(t, rp.AddDefinedSet(cs, false))

		npol := 1 + rnd.Intn(2)
		defs := make([]*oc.PolicyDefinition, 0, npol)
		for pi := 0; pi < npol; pi++ {
			nstmt := 1 + rnd.Intn(3)
			stmts := make([]oc.Statement, 0, nstmt)
			for si := 0; si < nstmt; si++ {
				st := oc.Statement{Name: fmt.Sprintf("p%d_s%d", pi, si)}
				if rnd.Intn(2) == 0 {
					st.Conditions.MatchPrefixSet = oc.MatchPrefixSet{PrefixSet: "ps", MatchSetOptions: pickMSO()}
				}
				if rnd.Intn(3) == 0 {
					st.Conditions.MatchNeighborSet = oc.MatchNeighborSet{NeighborSet: "ns", MatchSetOptions: pickMSO()}
				}
				if rnd.Intn(4) == 0 {
					// Non-whitelisted: forces the prover to "unknown".
					st.Conditions.BgpConditions.MatchCommunitySet = oc.MatchCommunitySet{CommunitySet: "cs"}
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
			pol, err := table.NewPolicy(def)
			require.NoError(t, err)
			require.NoError(t, rp.AddPolicy(pol, false))
			defs = append(defs, &oc.PolicyDefinition{Name: def.Name})
		}
		if rnd.Intn(10) != 0 { // sometimes leave the table id unassigned
			def := table.ROUTE_TYPE_REJECT
			switch rnd.Intn(3) {
			case 0:
				def = table.ROUTE_TYPE_ACCEPT
			case 1:
				def = table.ROUTE_TYPE_NONE
			}
			require.NoError(t, rp.AddPolicyAssignment(pRef.TableID(), table.POLICY_DIRECTION_EXPORT, defs, def))
		}

		// One destination per iteration; 2-4 sequential announce events
		// from a small source pool (collisions = implicit replace, the
		// reannounceKey leg), with occasional prefix-set transitions
		// between events.
		destPrefix := prefixPool[rnd.Intn(len(prefixPool))]
		oldSyncBody := func(peer *peer, newPath *table.Path) []*table.Path {
			dest := rib.GetDestination(newPath)
			if dest == nil {
				return nil
			}
			newLocalKey := newPath.GetLocalKey()
			// armPreclone=true: the pre-phase-3 body ran the per-path
			// short-circuit armed on every path.
			return s.syncRankedAddPathSetFromList(peer, bgp.RF_IPv4_UC, dest.GetKnownPathList(peer.TableID(), peer.AS()), &newLocalKey, true)
		}

		mkPath := func(source netip.Addr) *table.Path {
			nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(destPrefix))
			require.NoError(t, err)
			nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.9.9.9"))
			require.NoError(t, err)
			attrs := []bgp.PathAttributeInterface{
				bgp.NewPathAttributeOrigin(0),
				bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{65010})}),
				nh,
				bgp.NewPathAttributeMultiExitDisc(uint32(rnd.Intn(4))),
			}
			// Half the paths carry the community the "cs" set matches:
			// per-path attribute diversity at one destination, so a
			// future whitelist addition of an attribute-conditioned
			// Evaluate produces genuinely divergent verdicts and trips
			// the MAJOR-2(b) invariance assertion below.
			if rnd.Intn(2) == 0 {
				attrs = append(attrs, bgp.NewPathAttributeCommunities([]uint32{100<<16 | 100}))
			}
			return table.NewPath(bgp.RF_IPv4_UC, &table.PeerInfo{
				AS: 65010, LocalAS: 65001,
				Address: source, ID: source,
				LocalAddress: netip.MustParseAddr("1.1.1.1"),
				LocalID:      netip.MustParseAddr("1.1.1.1"),
			}, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
		}

		// Pre-seed 0-2 paths at the destination WITHOUT running a sync
		// event for them: known-but-never-synced paths model a fresh
		// ADD-PATH session's un-dumped destination, and they are the
		// shape that exposes a wrongly-hoisted verdict — the old body
		// PROMOTES an accepted unsent path on any event at the
		// destination, while an unsound skip returns nothing (the
		// reviewer's BLOCKER-1 repro: old body announced 1, wrapper 0).
		for n := rnd.Intn(3); n > 0; n-- {
			rib.Update(mkPath(netip.MustParseAddr(sourcePool[rnd.Intn(len(sourcePool))])))
		}

		nevents := 2 + rnd.Intn(3)
		for ev := 0; ev < nevents; ev++ {
			path := mkPath(netip.MustParseAddr(sourcePool[rnd.Intn(len(sourcePool))]))
			rib.Update(path)

			// The prover-invariance property runs BEFORE the output
			// differential (round-2 review new-2): it depends on neither
			// sync's output, and when an event violates both, this
			// message names the root-cause class where the count
			// divergence below only reports that something differed.
			if dest := rib.GetDestination(path); dest != nil {
				knownList := dest.GetKnownPathList(pRef.TableID(), pRef.AS())
				opts := &table.PolicyOptions{Info: pNew.peerInfo.Load()}
				if opts.Info.Address.IsValid() {
					// MAJOR-2(b) direct invariance property: under the
					// hoisted gate's preconditions (valid Info.Address;
					// this corpus is all non-VRF, non-RTC), every known
					// path must share newPath's prover verdict. Any
					// divergence — either direction, since newPath is
					// itself one of the known paths under some announce
					// order — would let the hoisted skip blank a live
					// path; a whitelist addition that reads per-path
					// state fails HERE even if no random announce order
					// trips the output differential below.
					want := rp.ProvablyRejectsPreClone(pNew.TableID(), table.POLICY_DIRECTION_EXPORT, path, opts)
					for _, known := range knownList {
						require.Equal(t, want,
							rp.ProvablyRejectsPreClone(pNew.TableID(), table.POLICY_DIRECTION_EXPORT, known, opts),
							"iter %d event %d: ProvablyRejectsPreClone verdict not destination-invariant for %s id %d",
							iter, ev, known.GetPrefix(), known.LocalID())
					}
				} else {
					// Coverage for the MAJOR-2(a) dimension: record when
					// the fallback actually split the destination's REAL
					// policy verdicts (the corpus has no mod actions, so
					// this ApplyPolicy probe mutates nothing).
					verdicts := map[bool]bool{}
					for _, known := range knownList {
						verdicts[rp.ApplyPolicy(pNew.TableID(), table.POLICY_DIRECTION_EXPORT, known, opts) != nil] = true
					}
					if len(verdicts) == 2 {
						mixedVerdictEvents++
					}
				}
			}

			ref := oldSyncBody(pRef, path)
			got := s.syncRankedAddPathSet(rib, pNew, bgp.RF_IPv4_UC, path, "")

			require.Equal(t, len(ref), len(got),
				"iter %d event %d: announcement count diverged", iter, ev)
			for i := range ref {
				assert.Equal(t, ref[i].GetLocalKey(), got[i].GetLocalKey(),
					"iter %d event %d entry %d: local key diverged", iter, ev, i)
				assert.Equal(t, ref[i].IsWithdraw, got[i].IsWithdraw,
					"iter %d event %d entry %d: withdraw flag diverged", iter, ev, i)
			}
			pRef.updateRoutes(ref...)
			pNew.updateRoutes(got...)

			// Adv-state parity over the destination's full known set:
			// stale or missing mutations (sent bits, send-max flags) are
			// exactly the ADD-PATH corruption constraint 4 forbids.
			if dest := rib.GetDestination(path); dest != nil {
				knownList := dest.GetKnownPathList(pRef.TableID(), pRef.AS())
				for _, known := range knownList {
					assert.Equal(t, pRef.hasPathAlreadyBeenSent(known), pNew.hasPathAlreadyBeenSent(known),
						"iter %d event %d: sent-state diverged for %s id %d", iter, ev, known.GetPrefix(), known.LocalID())
					assert.Equal(t, pRef.isPathSendMaxFiltered(known), pNew.isPathSendMaxFiltered(known),
						"iter %d event %d: send-max flag diverged for %s id %d", iter, ev, known.GetPrefix(), known.LocalID())
				}
			}
			totalEvents++
			announced += len(got)

			// Transition: mutate the LIVE prefix set between events, both
			// directions (append the destination prefix / remove it).
			if rnd.Intn(4) == 0 {
				entry := oc.Prefix{
					IpPrefix:        netip.MustParsePrefix(destPrefix),
					MasklengthRange: maskRanges[rnd.Intn(len(maskRanges))],
				}
				delta, err := table.NewPrefixSet(oc.PrefixSet{PrefixSetName: "ps", PrefixList: []oc.Prefix{entry}})
				require.NoError(t, err)
				if rnd.Intn(2) == 0 {
					require.NoError(t, rp.AddDefinedSet(delta, false))
				} else if err := rp.DeleteDefinedSet(delta, false); err != nil {
					// Removing an entry that is not in the set is a
					// legitimate no-op for this corpus.
					require.Contains(t, err.Error(), "not found")
				}
			}
		}
	}

	skips := s.precloneSyncSkips.Load() - skipsBefore
	t.Logf("events=%d announced=%d hoistedSkips=%d mixedVerdictEvents=%d",
		totalEvents, announced, skips, mixedVerdictEvents)
	require.NotZero(t, skips, "the hoisted skip never fired; the differential is vacuous")
	// Headroom note (round-2 review new-4): 141 observed at seed 1 vs the
	// 100 floor — the invalid-Info dimension consumes 25% of iterations
	// and never fires the skip. Deterministic, so no flake risk, but a
	// further skip-suppressing corpus dimension will trip this floor
	// before coverage is genuinely degenerate; rebalance then.
	require.GreaterOrEqual(t, skips, int64(100), "hoisted-skip coverage degenerated")
	require.NotZero(t, announced, "no event ever announced; the accept leg is uncovered")
	require.NotZero(t, mixedVerdictEvents,
		"no invalid-Info destination ever split verdicts across sources; the BLOCKER-1 hazard class is uncovered")
}
