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

// Tests for the R-212 asynchronous chunked export dump (export_dump.go) and
// the bounded send-loop marshal rounds (fsm.go).

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// exportDumpTestPrefixes returns n distinct /24 prefixes under 198.18.0.0/15
// (benchmarking range, RFC 2544).
func exportDumpTestPrefixes(t *testing.T, n int) []string {
	t.Helper()
	require.LessOrEqual(t, n, 2*256*256)
	out := make([]string, 0, n)
	for i := 0; len(out) < n; i++ {
		out = append(out, fmt.Sprintf("198.%d.%d.%d/32", 18+i/(256*256), i/256%256, i%256))
	}
	return out
}

func newExportDumpTestServer(t *testing.T) *BgpServer {
	t.Helper()
	s := NewBgpServer()
	go s.Serve()
	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65001,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)
	return s
}

// addExportDumpTestPeer registers an established-ready test peer directly in
// the neighbor map, mirroring the softResetOut test harness.
func addExportDumpTestPeer(t *testing.T, s *BgpServer, address string, gracefulRestart bool) *peer {
	t.Helper()
	peerAddr := netip.MustParseAddr(address)
	p := newPeerandInfo(t, 65001, 65002, address, s.globalRib)
	p.policy = s.policy
	p.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{
		bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_NONE,
	})
	if gracefulRestart {
		p.fsm.lock.Lock()
		conf := p.fsm.pConf.ReadCopy()
		conf.GracefulRestart.State.Enabled = true
		p.fsm.pConf.Update(&conf)
		p.fsm.lock.Unlock()
	}
	err := s.mgmtOperation(func() error {
		s.neighborMap[peerAddr] = p
		return nil
	}, true)
	require.NoError(t, err)
	t.Cleanup(func() {
		err := s.mgmtOperation(func() error {
			delete(s.neighborMap, peerAddr)
			return nil
		}, false)
		require.NoError(t, err)
		p.abortExportDump()
		cleanInfiniteChannel(p.fsm.outgoingCh)
	})
	return p
}

func establishMsg() *fsmMsg {
	return &fsmMsg{
		MsgType:     fsmMsgStateChange,
		MsgData:     bgp.BGP_FSM_ESTABLISHED,
		StateReason: newfsmStateReason(fsmOpenMsgNegotiated, nil, nil),
		timestamp:   time.Now(),
	}
}

// TestExportDumpEstablishChunksAndEOR: on ESTABLISHED the callback returns
// without generating the dump; the dump arrives asynchronously as bounded
// chunks, complete, with the EOR as the very last path (R-212 leg 1).
func TestExportDumpEstablishChunksAndEOR(t *testing.T) {
	s := newExportDumpTestServer(t)
	t.Cleanup(func() {
		require.NoError(t, s.StopBgp(context.Background(), &api.StopBgpRequest{}))
		s.bfdServer.Stop()
	})

	const numDests = 20000 // > 2 * exportDumpChunkPaths, forces >= 3 chunks
	prefixes := exportDumpTestPrefixes(t, numDests)
	paths := make([]*table.Path, 0, numDests)
	for _, prefix := range prefixes {
		paths = append(paths, makePath(t, prefix, "192.0.2.254", 0))
	}
	s.propagateUpdate(nil, paths)

	p := addExportDumpTestPeer(t, s, "10.0.0.1", true)

	start := time.Now()
	s.handleFSMMessage(p, establishMsg())
	callbackDuration := time.Since(start)
	// The FSM loop stores the state right after the callback returns; the
	// dump walk waits for it.
	p.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)

	// The pre-R-212 code walked the full RIB inside the callback. The async
	// version only bumps the dump generation; even with the race detector
	// this is far below a second.
	assert.Less(t, callbackDuration, 2*time.Second, "establish callback must not generate the dump synchronously")

	var chunks [][]*table.Path
	sawEOR := false
	deadline := time.After(20 * time.Second)
	for !sawEOR {
		select {
		case o := <-p.fsm.outgoingCh.Out():
			msg, ok := o.(*fsmOutgoingMsg)
			require.True(t, ok)
			chunks = append(chunks, msg.Paths)
			for i, path := range msg.Paths {
				if path.IsEOR() {
					sawEOR = true
					assert.Equal(t, len(msg.Paths)-1, i, "EOR must be the last path of the final chunk")
				}
			}
		case <-deadline:
			t.Fatal("timed out waiting for the dump EOR")
		}
	}

	require.GreaterOrEqual(t, len(chunks), 3, "dump must arrive in bounded chunks, not one message")
	total := 0
	for _, chunk := range chunks {
		require.LessOrEqual(t, len(chunk), exportDumpChunkPaths+1, "chunk exceeds the path bound")
		for _, path := range chunk {
			if path.IsEOR() {
				continue
			}
			require.False(t, path.IsWithdraw)
			total++
		}
	}
	assert.Equal(t, numDests, total, "dump must cover every destination exactly once")

	// Nothing may trail the EOR.
	select {
	case o := <-p.fsm.outgoingCh.Out():
		t.Fatalf("unexpected message after EOR: %#v", o)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestExportDumpSnapshotSeesPreEstablishUpdate: an update that lands between
// the establish callback and the walk's snapshot is part of the snapshot —
// the peer ends at the fresh value (the staleness window the async design
// closes by snapshotting after the ESTABLISHED store).
func TestExportDumpSnapshotSeesPreEstablishUpdate(t *testing.T) {
	s := newExportDumpTestServer(t)
	t.Cleanup(func() {
		require.NoError(t, s.StopBgp(context.Background(), &api.StopBgpRequest{}))
		s.bfdServer.Stop()
	})

	s.propagateUpdate(nil, []*table.Path{makePath(t, "192.0.2.0/32", "192.0.2.254", 100)})

	p := addExportDumpTestPeer(t, s, "10.0.0.1", true)
	s.handleFSMMessage(p, establishMsg())
	// The walk is now waiting for the ESTABLISHED store. Replace the path
	// while the peer is not yet advertising (needToAdvertise is false, so
	// live propagation skips it — pre-R-212 this update would have been
	// lost if the dump had already passed the destination).
	s.propagateUpdate(nil, []*table.Path{makePath(t, "192.0.2.0/32", "192.0.2.254", 200)})
	p.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)

	select {
	case o := <-p.fsm.outgoingCh.Out():
		msg, ok := o.(*fsmOutgoingMsg)
		require.True(t, ok)
		var got *table.Path
		for _, path := range msg.Paths {
			if !path.IsEOR() {
				require.Nil(t, got, "expected exactly one dump path")
				got = path
			}
		}
		require.NotNil(t, got)
		comms := got.GetCommunities()
		require.Len(t, comms, 1)
		assert.Equal(t, uint32(200), comms[0], "dump must carry the post-callback value")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the dump chunk")
	}
}

// TestExportDumpDirtySkipAndAbort exercises the flush protocol directly:
// destinations claimed by live propagation are skipped with their
// bookkeeping untouched, and a bumped generation suppresses the flush
// entirely (late-chunk guard).
func TestExportDumpDirtySkipAndAbort(t *testing.T) {
	s := newExportDumpTestServer(t)
	t.Cleanup(func() {
		require.NoError(t, s.StopBgp(context.Background(), &api.StopBgpRequest{}))
		s.bfdServer.Stop()
	})
	p := newPeerandInfo(t, 65001, 65002, "10.0.0.1", s.globalRib)
	t.Cleanup(func() { cleanInfiniteChannel(p.fsm.outgoingCh) })

	d := &p.dump
	d.mu.Lock()
	d.gen++
	gen := d.gen
	d.dirty = make(map[table.PathDestLocalKey]struct{})
	d.mu.Unlock()

	clean := makePath(t, "192.0.2.0/32", "192.0.2.254", 0)
	stale := makePath(t, "192.0.2.1/32", "192.0.2.254", 0)

	// Live propagation claims the second destination.
	p.markExportDumpDirty([]*table.Path{stale})

	entries := []exportDumpChunkEntry{
		{key: clean.GetDestLocalKey(), paths: []*table.Path{clean}},
		{key: stale.GetDestLocalKey(), paths: []*table.Path{stale}},
	}
	sent, skipped, ok := s.flushExportDumpChunk(p, gen, entries, nil)
	require.True(t, ok)
	assert.Equal(t, 1, sent)
	assert.Equal(t, 1, skipped)
	assert.True(t, p.hasPathAlreadyBeenSent(clean), "flushed path must be booked as sent")
	assert.False(t, p.hasPathAlreadyBeenSent(stale), "dirty destination bookkeeping belongs to live propagation")

	select {
	case o := <-p.fsm.outgoingCh.Out():
		msg, ok := o.(*fsmOutgoingMsg)
		require.True(t, ok)
		require.Len(t, msg.Paths, 1)
		assert.Equal(t, "192.0.2.0/32", msg.Paths[0].GetPrefix())
	case <-time.After(time.Second):
		t.Fatal("expected the clean destination to be enqueued")
	}

	// Peer-down invalidates the generation; a late chunk must be dropped
	// whole — no enqueue, no bookkeeping.
	p.abortExportDump()
	late := makePath(t, "192.0.2.2/32", "192.0.2.254", 0)
	sent, _, ok = s.flushExportDumpChunk(p, gen, []exportDumpChunkEntry{{key: late.GetDestLocalKey(), paths: []*table.Path{late}}}, nil)
	assert.False(t, ok)
	assert.Zero(t, sent)
	assert.False(t, p.hasPathAlreadyBeenSent(late))
	select {
	case o := <-p.fsm.outgoingCh.Out():
		t.Fatalf("aborted dump enqueued a chunk: %#v", o)
	case <-time.After(100 * time.Millisecond):
	}
}

// TestExportDumpAbortOnPeerDown: a session that dies before the walk starts
// producing (here: before the ESTABLISHED store) never emits dump traffic —
// the PeerDown handling bumps the generation before resetAdvertisedRoutes.
func TestExportDumpAbortOnPeerDown(t *testing.T) {
	s := newExportDumpTestServer(t)
	t.Cleanup(func() {
		require.NoError(t, s.StopBgp(context.Background(), &api.StopBgpRequest{}))
		s.bfdServer.Stop()
	})

	s.propagateUpdate(nil, []*table.Path{makePath(t, "192.0.2.0/32", "192.0.2.254", 0)})
	p := addExportDumpTestPeer(t, s, "10.0.0.1", true)

	s.handleFSMMessage(p, establishMsg())
	// The walk is waiting for the ESTABLISHED store. Take the session down
	// instead — the establish callback recorded SessionState=established, so
	// this runs the PeerDown branch, which aborts the dump.
	s.handleFSMMessage(p, &fsmMsg{
		MsgType:     fsmMsgStateChange,
		MsgData:     bgp.BGP_FSM_IDLE,
		StateReason: newfsmStateReason(fsmHoldTimerExpired, nil, nil),
		timestamp:   time.Now(),
	})

	select {
	case o := <-p.fsm.outgoingCh.Out():
		t.Fatalf("dump emitted traffic for a dead session: %#v", o)
	case <-time.After(300 * time.Millisecond):
	}
}

// TestExportDumpAddPathWithdrawBackfillDuringDump: a withdraw that lands on
// an ADD-PATH SendMax peer while a dump is in flight — before the dump has
// flushed the destination — must announce the surviving ranked set alongside
// the withdraw. The pre-fix flag-based backfill promoted only paths flagged
// send-max-filtered, which is nothing mid-dump; since the delta also marks
// the destination dirty (the dump then skips it), the surviving paths would
// never have reached the peer at all.
func TestExportDumpAddPathWithdrawBackfillDuringDump(t *testing.T) {
	s := newExportDumpTestServer(t)
	t.Cleanup(func() {
		require.NoError(t, s.StopBgp(context.Background(), &api.StopBgpRequest{}))
		s.bfdServer.Stop()
	})

	peerAddr := netip.MustParseAddr("10.0.0.1")
	p := newPeerandInfo(t, 65001, 65002, peerAddr.String(), s.globalRib)
	p.policy = s.policy
	p.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{
		bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_SEND,
	})
	p.fsm.lock.Lock()
	conf := p.fsm.pConf.ReadCopy()
	foundFamily := false
	for i := range conf.AfiSafis {
		if conf.AfiSafis[i].State.Family != bgp.RF_IPv4_UC {
			continue
		}
		conf.AfiSafis[i].AddPaths.Config.SendMax = 1
		conf.AfiSafis[i].AddPaths.State.SendMax = 1
		foundFamily = true
	}
	p.fsm.pConf.Update(&conf)
	p.fsm.lock.Unlock()
	require.True(t, foundFamily)
	err := s.mgmtOperation(func() error {
		s.neighborMap[peerAddr] = p
		return nil
	}, true)
	require.NoError(t, err)
	t.Cleanup(func() {
		err := s.mgmtOperation(func() error {
			delete(s.neighborMap, peerAddr)
			return nil
		}, false)
		require.NoError(t, err)
		p.abortExportDump()
		cleanInfiniteChannel(p.fsm.outgoingCh)
	})

	makeSourcePath := func(source string, isWithdraw bool) *table.Path {
		t.Helper()
		nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("192.0.2.0/32"))
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
		}, bgp.PathNLRI{NLRI: nlri}, isWithdraw, []bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(0),
			bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
				bgp.NewAs4PathParam(2, []uint32{65010}),
			}),
			nextHop,
		}, time.Now(), false)
	}

	// Seed two paths for the destination while the peer is NOT yet
	// advertising: no live delta runs, no bookkeeping exists — the state a
	// destination is in before the dump walk reaches it.
	pathA := makeSourcePath("10.0.0.2", false)
	pathB := makeSourcePath("10.0.0.3", false)
	s.propagateUpdate(nil, []*table.Path{pathA, pathB})

	// A dump is in flight (installed directly for determinism, mirroring
	// startExportDump), and the peer is now advertising.
	d := &p.dump
	d.mu.Lock()
	d.gen++
	gen := d.gen
	d.dirty = make(map[table.PathDestLocalKey]struct{})
	d.inflight = []bgp.Family{bgp.RF_IPv4_UC}
	d.mu.Unlock()
	p.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)

	// Withdraw one of the two paths before the dump flushes the destination.
	s.propagateUpdate(nil, []*table.Path{makeSourcePath("10.0.0.2", true)})

	var got []*table.Path
	select {
	case o := <-p.fsm.outgoingCh.Out():
		msg, ok := o.(*fsmOutgoingMsg)
		require.True(t, ok)
		got = msg.Paths
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the withdraw delta")
	}

	var withdraws, announces []*table.Path
	for _, path := range got {
		require.False(t, path.IsEOR())
		if path.IsWithdraw {
			withdraws = append(withdraws, path)
		} else {
			announces = append(announces, path)
		}
	}
	require.Len(t, withdraws, 1)
	assert.Equal(t, pathA.LocalID(), withdraws[0].LocalID())
	require.Len(t, announces, 1, "the surviving ranked path must be announced with the withdraw")
	assert.Equal(t, pathB.LocalID(), announces[0].LocalID())
	assert.True(t, p.hasPathAlreadyBeenSent(announces[0]), "the announced survivor must be booked as sent")

	// The delta claimed the destination: a late dump flush for it must be
	// skipped, not overwrite the fresh state.
	staleEntry := exportDumpChunkEntry{key: pathA.GetDestLocalKey(), paths: []*table.Path{pathA}}
	sent, skipped, ok := s.flushExportDumpChunk(p, gen, []exportDumpChunkEntry{staleEntry}, nil)
	require.True(t, ok)
	assert.Zero(t, sent)
	assert.Equal(t, 1, skipped)
}

// TestAddPathWithdrawFastSkipNeverAdvertised pins the R-230 pre-filterpath
// fast skip on the ADD-PATH withdraw backfill in steady state (no dump in
// flight): a withdraw for a path never booked as sent to the peer produces
// no outgoing traffic and clears a stale send-max flag, while a withdraw for
// a sent path (same destination, different LocalID — the per-LocalID keying
// the fast skip relies on pre-filterpath) still reaches the wire.
func TestAddPathWithdrawFastSkipNeverAdvertised(t *testing.T) {
	s := newExportDumpTestServer(t)
	t.Cleanup(func() {
		require.NoError(t, s.StopBgp(context.Background(), &api.StopBgpRequest{}))
		s.bfdServer.Stop()
	})

	peerAddr := netip.MustParseAddr("10.0.0.1")
	p := newPeerandInfo(t, 65001, 65002, peerAddr.String(), s.globalRib)
	p.policy = s.policy
	p.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{
		bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_SEND,
	})
	err := s.mgmtOperation(func() error {
		s.neighborMap[peerAddr] = p
		return nil
	}, true)
	require.NoError(t, err)
	t.Cleanup(func() {
		err := s.mgmtOperation(func() error {
			delete(s.neighborMap, peerAddr)
			return nil
		}, false)
		require.NoError(t, err)
		cleanInfiniteChannel(p.fsm.outgoingCh)
	})

	makeSourcePath := func(source string, isWithdraw bool) *table.Path {
		t.Helper()
		nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("192.0.2.0/32"))
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
		}, bgp.PathNLRI{NLRI: nlri}, isWithdraw, []bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(0),
			bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
				bgp.NewAs4PathParam(2, []uint32{65010}),
			}),
			nextHop,
		}, time.Now(), false)
	}

	// Seed two paths for one destination while the peer is not advertising
	// (no bookkeeping), then book only pathB as sent — the state a scoped-
	// export peer is in after its establish dump announced the accepted
	// subset. pathA additionally carries a stale send-max flag.
	pathA := makeSourcePath("10.0.0.2", false)
	pathB := makeSourcePath("10.0.0.3", false)
	s.propagateUpdate(nil, []*table.Path{pathA, pathB})
	p.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)
	p.updateRoutes(pathB)
	p.setPathSendMaxFiltered(pathA)

	// Withdraw the never-sent path: the fast skip must produce NO outgoing
	// traffic and must clear the stale flag.
	s.propagateUpdate(nil, []*table.Path{makeSourcePath("10.0.0.2", true)})
	select {
	case o := <-p.fsm.outgoingCh.Out():
		t.Fatalf("never-advertised withdraw reached the wire: %#v", o)
	case <-time.After(300 * time.Millisecond):
	}
	assert.False(t, p.isPathSendMaxFiltered(pathA), "stale send-max flag must be cleared by the fast skip")

	// Withdraw the sent path: same destination, different LocalID — must
	// still reach the wire.
	s.propagateUpdate(nil, []*table.Path{makeSourcePath("10.0.0.3", true)})
	select {
	case o := <-p.fsm.outgoingCh.Out():
		msg, ok := o.(*fsmOutgoingMsg)
		require.True(t, ok)
		require.Len(t, msg.Paths, 1)
		assert.True(t, msg.Paths[0].IsWithdraw)
		assert.Equal(t, pathB.LocalID(), msg.Paths[0].LocalID())
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the sent path's withdraw")
	}
}

// TestExportDumpLiveUpdatesDuringDumpConverge races live propagation against
// a running establish dump: whatever the interleaving (dirty-skip before the
// dump reaches the destination, or fresh update enqueued after a stale
// chunk), the last action per NLRI on the queue must carry the fresh value,
// and no destination may be lost.
func TestExportDumpLiveUpdatesDuringDumpConverge(t *testing.T) {
	s := newExportDumpTestServer(t)
	t.Cleanup(func() {
		require.NoError(t, s.StopBgp(context.Background(), &api.StopBgpRequest{}))
		s.bfdServer.Stop()
	})

	const numDests = 12000 // two chunks, dump takes long enough to race
	const numChanged = 500
	prefixes := exportDumpTestPrefixes(t, numDests)
	paths := make([]*table.Path, 0, numDests)
	for _, prefix := range prefixes {
		paths = append(paths, makePath(t, prefix, "192.0.2.254", 100))
	}
	s.propagateUpdate(nil, paths)

	p := addExportDumpTestPeer(t, s, "10.0.0.1", true)
	s.handleFSMMessage(p, establishMsg())
	p.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)

	// Race the walk: replace every 24th destination with a fresh path while
	// chunks are being flushed. Spread across the whole prefix range so some
	// land before and some after the walk passes them.
	changed := make(map[string]struct{}, numChanged)
	for i := range numChanged {
		prefix := prefixes[i*(numDests/numChanged)]
		changed[prefix] = struct{}{}
		s.propagateUpdate(nil, []*table.Path{makePath(t, prefix, "192.0.2.254", 999)})
	}

	// Drain everything: dump chunks, EOR, and live deltas (which may trail
	// the EOR). Stop once the queue stays silent.
	var queued []*table.Path
	lastCommunity := make(map[string]uint32, numDests)
	deadline := time.After(30 * time.Second)
	for {
		select {
		case o := <-p.fsm.outgoingCh.Out():
			msg, ok := o.(*fsmOutgoingMsg)
			require.True(t, ok)
			for _, path := range msg.Paths {
				if path.IsEOR() {
					continue
				}
				require.False(t, path.IsWithdraw)
				queued = append(queued, path)
				comms := path.GetCommunities()
				require.Len(t, comms, 1)
				lastCommunity[path.GetPrefix()] = comms[0]
			}
			continue
		case <-time.After(2 * time.Second):
		case <-deadline:
			t.Fatal("queue never went silent")
		}
		break
	}

	require.Len(t, lastCommunity, numDests, "every destination must be advertised at least once")
	for prefix, comm := range lastCommunity {
		if _, ok := changed[prefix]; ok {
			assert.Equal(t, uint32(999), comm, "changed destination %s must end at the fresh value", prefix)
		} else {
			assert.Equal(t, uint32(100), comm, "unchanged destination %s must keep the original value", prefix)
		}
	}

	// End-to-end: replay the drained queue through the send loop's actual
	// round slicing and CreateUpdateMsgFromPaths, and assert the final
	// on-wire state per NLRI. This is where a stale dump copy could beat a
	// fresh live copy (the packers emit announcement groups in map order);
	// the wire-key dedupe within a round plus FIFO order across rounds must
	// make the fresh value land last regardless.
	const roundSize = 8192 // maxPathsPerSendRound in fsm.go sendMessageloop
	wire := make(map[string]uint32, numDests)
	for len(queued) > 0 {
		n := min(len(queued), roundSize)
		round := queued[:n]
		queued = queued[n:]
		for _, msg := range table.CreateUpdateMsgFromPaths(round) {
			u := msg.Body.(*bgp.BGPUpdate)
			require.Empty(t, u.WithdrawnRoutes)
			var comm uint32
			hasComm := false
			for _, attr := range u.PathAttributes {
				if c, ok := attr.(*bgp.PathAttributeCommunities); ok {
					require.Len(t, c.Value, 1)
					comm = c.Value[0]
					hasComm = true
				}
			}
			if len(u.NLRI) > 0 {
				require.True(t, hasComm)
			}
			for _, nlri := range u.NLRI {
				wire[nlri.NLRI.String()] = comm
			}
		}
	}
	require.Len(t, wire, numDests, "every destination must reach the wire")
	for prefix, comm := range wire {
		if _, ok := changed[prefix]; ok {
			assert.Equal(t, uint32(999), comm, "changed destination %s must end at the fresh value on the wire", prefix)
		} else {
			assert.Equal(t, uint32(100), comm, "unchanged destination %s must keep the original value on the wire", prefix)
		}
	}
}

// slowWriteConn throttles writes so a bulk UPDATE batch takes long enough to
// span keepalive ticks.
type slowWriteConn struct {
	net.Conn
	delay time.Duration
}

func (c *slowWriteConn) Write(b []byte) (int, error) {
	time.Sleep(c.delay)
	return c.Conn.Write(b)
}

// TestSendMessageloopKeepaliveDuringBulkUpdates: with an oversized queued
// batch on a slow connection, keepalives are serviced between bounded
// marshal rounds instead of waiting for the whole batch (R-212 leg 2). The
// pre-R-212 loop sent zero keepalives until the entire batch was written.
func TestSendMessageloopKeepaliveDuringBulkUpdates(t *testing.T) {
	m := NewMockConnection()
	_, h := makePeerAndHandler(m)
	t.Cleanup(func() { h.outgoing.Close(); m.Close() })

	// 1s keepalive ticker (the minimum keepaliveTicker grants).
	h.fsm.lock.Lock()
	conf := h.fsm.pConf.ReadCopy()
	conf.Timers.State.NegotiatedHoldTime = 3
	conf.Timers.State.KeepaliveInterval = 1
	h.fsm.pConf.Update(&conf)
	h.fsm.lock.Unlock()

	// Five marshal rounds; ~50ms per wire write makes each round span a few
	// hundred ms, so the 1s ticker fires while rounds are still pending.
	const numPaths = 5 * 8192
	prefixes := exportDumpTestPrefixes(t, numPaths)
	paths := make([]*table.Path, 0, numPaths)
	for _, prefix := range prefixes {
		paths = append(paths, makePath(t, prefix, "192.168.1.1", 0))
	}

	ctx, cancel := context.WithCancel(context.Background())
	stateReasonCh := make(chan fsmStateReason, 3)
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go h.sendMessageloop(ctx, &slowWriteConn{Conn: m, delay: 50 * time.Millisecond}, stateReasonCh, wg)

	h.outgoing.In() <- &fsmOutgoingMsg{Paths: paths}

	assert.Eventually(t, func() bool {
		return countNLRIs(parseBGPUpdates(t, m.GetSentMessages())) >= numPaths
	}, 60*time.Second, 100*time.Millisecond, "timed out waiting for the bulk batch")

	cancel()
	wg.Wait()

	msgs := parseBGPUpdates(t, m.GetSentMessages())
	assert.Equal(t, numPaths, countNLRIs(msgs), "every path exactly once: no drops, no duplicates across marshal rounds")
	firstUpdate, lastUpdate := -1, -1
	keepalives := make([]int, 0, 8)
	for i, msg := range msgs {
		switch msg.Header.Type {
		case bgp.BGP_MSG_UPDATE:
			if firstUpdate < 0 {
				firstUpdate = i
			}
			lastUpdate = i
		case bgp.BGP_MSG_KEEPALIVE:
			keepalives = append(keepalives, i)
		}
	}
	require.GreaterOrEqual(t, firstUpdate, 0)
	interleaved := false
	for _, k := range keepalives {
		if k > firstUpdate && k < lastUpdate {
			interleaved = true
			break
		}
	}
	assert.True(t, interleaved, "keepalive must be serviced between marshal rounds of one bulk batch (got %d keepalives, updates spanning [%d,%d])", len(keepalives), firstUpdate, lastUpdate)
}
