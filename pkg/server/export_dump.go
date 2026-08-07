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

// Bendrr fork (R-212): asynchronous, chunked full-RIB export dumps.
//
// Upstream generates a peer's full export set (session establish, soft reset
// out, ROUTE-REFRESH, GR sync-finished) synchronously on the FSM callback:
// the whole Loc-RIB is walked and filtered before the send/recv loops start,
// and the result is enqueued as a single fsmOutgoingMsg. At Bendrr scale
// (~20M paths) both phases take minutes of wire silence, so the peer's hold
// timer always wins and the session flaps forever (backlog R-212, findings
// doc U7).
//
// This file moves the walk off the FSM callback into a per-peer dump
// goroutine, following the F9 would_export.go scale discipline:
//
//   - The caller only bumps the dump generation and installs a fresh
//     dirty-destination set, then returns; keepalives start immediately.
//   - The dump goroutine waits for the ESTABLISHED state store (establish
//     sites only), snapshots the per-family destination lists (pointer
//     copies under table shard read locks — no server lock held), walks the
//     snapshot through the normal export pipeline (filterpath + D-034
//     ranked SendMax slots), and enqueues bounded fsmOutgoingMsg chunks.
//     EOR markers ride with the final chunk, preserving upstream framing.
//
// Ordering versus live propagation (the design decision called out in the
// R-212 plan): live propagation to the peer is NOT suppressed while a dump
// runs — it flows through propagateUpdateToNeighbors as usual and calls
// markExportDumpDirty with its output paths at enqueue time. The walk drops
// dirty destinations at chunk-flush time, atomically under the dump mutex.
// This converges for every interleaving:
//
//   - live marks + enqueues before the flush checks: the walk skips the
//     destination; the live delta is complete on its own because per-dest
//     sent-state was empty, so ranked ADD-PATH sync re-announces the full
//     top-SendMax set and plain-peer deltas are idempotent replaces;
//   - the flush enqueues a stale copy before live marks: the live update is
//     enqueued after it in FIFO order. The send loop slices the coalesced
//     queue into bounded marshal rounds that preserve that order, and
//     within one round CreateUpdateMsgFromPaths keeps only the last action
//     per *wire* key (the local path ID is ignored for families without
//     ADD-PATH send, where it is not serialized) — so across rounds the
//     later round lands later on the wire, and within a round the later
//     action is the only survivor: the fresh state wins either way;
//   - a live delta that produces NO output for a plain peer implies the
//     best path did not change, so the snapshot copy is still correct and
//     must not be skipped — which is exactly why marking happens at
//     enqueue time, not at processing time.
//
// Updates that land before the walk's snapshot are simply part of the
// snapshot: the walk snapshots after the ESTABLISHED store, so nothing can
// fall between "too late for the snapshot" and "too early for live
// propagation".
//
// Abort: the generation is bumped on PeerDown (before resetAdvertisedRoutes)
// and in peer.stopFSM (before the FSM loop can close outgoingCh), and by any
// superseding dump. The walk re-checks the generation under the dump mutex
// at every flush, so a dead session stops the walk between chunks and a late
// chunk can never be enqueued after the channel is closed: the abort path
// serializes behind any in-flight flush on the dump mutex.
//
// A superseding dump (e.g. a ROUTE-REFRESH received while the establish dump
// is still running) unions the unfinished families of the dump it aborts so
// coverage is never lost, and merges its option flags conservatively:
// withdraw-filtered semantics win over the GR-deferral withdraw-stripping
// optimization when the two mix (sending a withdraw during deferral is
// protocol-legal, merely redundant; losing one is not).
//
// The dirty set is bounded by the number of distinct destinations that
// live-churn touches while a dump is in flight, and it is dropped when the
// walk finishes or aborts. The theoretical worst case (every destination
// churned mid-dump) is the same order of heap as the snapshot the walk
// holds; at Bendrr churn rates the realistic footprint is a small fraction
// of that, for the dump's duration only.

import (
	"log/slog"
	"sync"
	"time"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

const (
	// exportDumpChunkPaths bounds the paths per enqueued fsmOutgoingMsg so
	// the send loop marshals bounded batches between keepalives (sized
	// against the send loop's own per-round path bound; see fsm.go).
	exportDumpChunkPaths = 8192
	// exportDumpQueueHighWater pauses the walk while the peer's outgoing
	// queue is this many messages deep, so a slow peer socket bounds the
	// dump's memory footprint instead of the whole dump sitting in the
	// infinite channel at once.
	exportDumpQueueHighWater = 64
	// exportDumpAbortCheckDests is how many destinations the walk processes
	// between generation checks when nothing is being flushed (e.g. long
	// runs of policy-filtered destinations), so a dead session stops the
	// walk promptly instead of at the next flush.
	exportDumpAbortCheckDests = 4096

	exportDumpBackpressurePoll = 10 * time.Millisecond
	exportDumpEstablishPoll    = 100 * time.Microsecond
)

// exportDumpState is the per-peer coordination point between the dump walk,
// live propagation and the peer lifecycle. Its mutex is a leaf lock: nothing
// else is acquired while holding it except peer.advMu and the outgoing
// channel enqueue (both leaves themselves).
type exportDumpState struct {
	mu sync.Mutex
	// gen invalidates the in-flight walk when bumped. Bumped by every new
	// dump, by PeerDown and by stopFSM.
	gen uint64
	// dirty is non-nil while a walk is in flight and records destinations
	// that live propagation has advertised (or withdrawn) since the dump
	// started; the walk skips them at flush time. Keys are the output
	// paths' dest-local keys, which match on both sides including the VRF
	// ToLocal translation.
	dirty map[table.PathDestLocalKey]struct{}
	// inflight is the current walk's full requested family set (not
	// narrowed as families complete — a supersede conservatively re-dumps
	// them all); a superseding dump unions it into its own request, merging
	// the option flags below so the aborted dump's semantics are not lost.
	inflight []bgp.Family
	// inflightWithdrawFiltered / inflightDropWithdraws mirror the in-flight
	// dump's exportDumpOpts flags (meaningful only while inflight is
	// non-empty).
	inflightWithdrawFiltered bool
	inflightDropWithdraws    bool
}

// exportDumpOpts selects the per-site behavior of a dump. All converted
// sites send EORs per the upstream rule (GR enabled, or the RTC family).
type exportDumpOpts struct {
	families []bgp.Family
	// withdrawFiltered replays soft-reset-out semantics: candidates the
	// export policy now rejects are withdrawn if they were previously sent.
	withdrawFiltered bool
	// dropWithdraws replays GR deferral-expiry semantics: withdraw paths
	// (e.g. LLGR-stale clones) are stripped from the dump.
	dropWithdraws bool
}

// markExportDumpDirty records the destinations of live-propagated output
// paths so an in-flight dump walk will not overwrite them with snapshot
// state. Callers pass the exact path slice they enqueue; nil paths and EORs
// are ignored. No-op when no dump is in flight.
func (peer *peer) markExportDumpDirty(paths []*table.Path) {
	d := &peer.dump
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.dirty == nil {
		return
	}
	for _, p := range paths {
		if p == nil || p.IsEOR() {
			continue
		}
		d.dirty[p.GetDestLocalKey()] = struct{}{}
	}
}

// abortExportDump invalidates any in-flight dump walk for the peer. Called
// on PeerDown before resetAdvertisedRoutes (so no chunk bookkeeping survives
// the reset) and from peer.stopFSM before the FSM loop can close the
// outgoing channel (an in-flight flush holds the dump mutex across its
// enqueue, so serializing on it here guarantees no enqueue after close).
func (peer *peer) abortExportDump() {
	d := &peer.dump
	d.mu.Lock()
	defer d.mu.Unlock()
	d.gen++
	d.dirty = nil
	d.inflight = nil
	d.inflightWithdrawFiltered = false
	d.inflightDropWithdraws = false
}

func (peer *peer) exportDumpAborted(gen uint64) bool {
	d := &peer.dump
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.gen != gen
}

// unionFamilies returns a ∪ b preserving a's order.
func unionFamilies(a, b []bgp.Family) []bgp.Family {
	seen := make(map[bgp.Family]struct{}, len(a)+len(b))
	out := make([]bgp.Family, 0, len(a)+len(b))
	for _, fs := range [][]bgp.Family{a, b} {
		for _, f := range fs {
			if _, ok := seen[f]; ok {
				continue
			}
			seen[f] = struct{}{}
			out = append(out, f)
		}
	}
	return out
}

// startExportDump replaces the synchronous full-dump sites. It must be
// called with s.shared.mu held (read or write), like the sites it replaces.
// It returns as soon as the walk goroutine is spawned.
func (s *BgpServer) startExportDump(peer *peer, o exportDumpOpts) {
	if len(o.families) == 0 {
		return
	}
	if peer.isSecondaryRouteEnabled() {
		// Route-server secondary-route mode keeps the legacy synchronous
		// dump: its export set comes from sendSecondaryRoutes over the
		// route-server RIB, which the chunked walk does not model. Bendrr
		// runs no route-server clients.
		s.getBestFromLocalCallback(peer, o.families, true, true, func(paths, filtered []*table.Path) {
			paths = applyLegacyDumpOpts(peer, o, paths, filtered)
			if len(paths) > 0 {
				peer.updateRoutes(paths...)
				sendfsmOutgoingMsg(peer, paths)
			}
		})
		return
	}

	// Barrier: briefly acquire the route-refresh write lock so the dump is
	// ordered after any live propagation already in flight for this peer
	// (their output either precedes the snapshot or marks dirty). This also
	// preserves the refresh-vs-propagation serialization the tests pin,
	// without holding the lock across the walk — holding it for the walk's
	// duration is exactly the wedge R-212 removes.
	peer.routeRefreshInProgress.Lock()
	//nolint:staticcheck // SA2001: empty critical section is the point — barrier only.
	peer.routeRefreshInProgress.Unlock()

	d := &peer.dump
	d.mu.Lock()
	d.gen++
	gen := d.gen
	d.dirty = make(map[table.PathDestLocalKey]struct{})
	if len(d.inflight) > 0 {
		// Superseding an unfinished dump: take over its family debt and
		// merge its semantics. Withdraw coverage must never be lost, so
		// withdrawFiltered is sticky; the deferral-only withdraw-stripping
		// optimization survives only when both dumps asked for it.
		o.families = unionFamilies(o.families, d.inflight)
		o.withdrawFiltered = o.withdrawFiltered || d.inflightWithdrawFiltered
		o.dropWithdraws = o.dropWithdraws && d.inflightDropWithdraws
	}
	d.inflight = o.families
	d.inflightWithdrawFiltered = o.withdrawFiltered
	d.inflightDropWithdraws = o.dropWithdraws
	d.mu.Unlock()

	go s.runExportDump(peer, o, gen)
}

// applyLegacyDumpOpts reproduces the pre-R-212 softResetOut callback
// behavior for the synchronous fallback path.
func applyLegacyDumpOpts(peer *peer, o exportDumpOpts, paths, filtered []*table.Path) []*table.Path {
	if o.withdrawFiltered && len(filtered) > 0 {
		withdrawals := make([]*table.Path, 0, len(filtered))
		for _, path := range filtered {
			if path == nil || path.IsEOR() {
				continue
			}
			if !peer.IsFamilyEnabled(path.GetFamily()) {
				continue
			}
			if !peer.hasPathAlreadyBeenSent(path) {
				continue
			}
			withdrawals = append(withdrawals, path.Clone(true))
		}
		paths = append(withdrawals, paths...)
	}
	if o.dropWithdraws {
		l := make([]*table.Path, 0, len(paths))
		for _, p := range paths {
			if !p.IsWithdraw {
				l = append(l, p)
			}
		}
		paths = l
	}
	return paths
}

type exportDumpDest struct {
	candidates []*table.Path
}

type exportDumpFamily struct {
	family bgp.Family      // global-space family whose table was walked
	sel    exportSelection // active only for ADD-PATH send peers with a selection cut
	dests  []exportDumpDest
}

// snapshotExportDump captures the peer-visible candidate paths per family as
// pointer copies. Table reads are shard-locked and the returned destination
// snapshots are immutable, so this is safe from any goroutine and the result
// can be walked without locks (F9 discipline).
func (s *BgpServer) snapshotExportDump(peer *peer, families []bgp.Family) []*exportDumpFamily {
	id, as := peer.TableID(), peer.AS()
	out := make([]*exportDumpFamily, 0, len(families))
	for _, family := range peer.toGlobalFamilies(families) {
		tbl, ok := peer.localRib.GetTable(family)
		if !ok {
			continue
		}
		fam := &exportDumpFamily{family: family}
		addPath := peer.isAddPathSendEnabled(family)
		if addPath {
			fam.sel = peer.exportSelection(family)
		}
		for _, dst := range tbl.GetDestinations() {
			var candidates []*table.Path
			if addPath {
				candidates = dst.GetKnownPathList(id, as)
			} else if best := dst.GetBestPath(id, as); best != nil {
				candidates = []*table.Path{best}
			}
			if len(candidates) == 0 {
				continue
			}
			fam.dests = append(fam.dests, exportDumpDest{candidates: candidates})
		}
		out = append(out, fam)
	}
	return out
}

// exportDumpChunkEntry is one destination's contribution to a chunk. The
// per-path SendMax flag mutations are recorded here and applied at flush
// time so that dirty destinations (owned by live propagation) keep the flags
// the live path computed from fresh state.
//
// Known benign staleness: a snapshot path that was withdrawn mid-dump
// without producing live output (it was send-max-suppressed, so the
// withdraw was skipped and the destination not marked dirty) can still get
// its filtered flag set here, and destination localIDs are reused. A later
// path inheriting the ID may briefly read as suppressed until the next
// update or ranked sync for that destination rewrites the flags.
type exportDumpChunkEntry struct {
	key              table.PathDestLocalKey
	paths            []*table.Path // withdraws (refresh mode) then announcements
	setMaxFiltered   []*table.Path
	unsetMaxFiltered []*table.Path
}

// evalExportDumpDest runs one snapshot destination through the export
// pipeline. It performs no peer state mutation — everything is recorded in
// the returned entry. ok is false when the destination contributes nothing.
func (s *BgpServer) evalExportDumpDest(peer *peer, fam *exportDumpFamily, dd exportDumpDest, o exportDumpOpts) (exportDumpChunkEntry, bool) {
	var e exportDumpChunkEntry
	haveKey := false
	sel := newExportSelector(fam.sel)
	var announce []*table.Path
	for _, path := range dd.candidates {
		fp := s.filterpath(peer, path, nil)
		if fp == nil {
			if o.withdrawFiltered {
				w := filteredPathForPeer(peer, path)
				if w == nil || w.IsEOR() || !peer.IsFamilyEnabled(w.GetFamily()) || !peer.hasPathAlreadyBeenSent(w) {
					continue
				}
				if !haveKey {
					e.key = w.GetDestLocalKey()
					haveKey = true
				}
				e.paths = append(e.paths, w.Clone(true))
			}
			continue
		}
		if !haveKey {
			e.key = fp.GetDestLocalKey()
			haveKey = true
		}
		if fam.sel.active() {
			// Selection runs on the snapshot Loc-RIB path (the attributes
			// ranking saw), not the post-policy rewrite fp.
			if !sel.admit(path) {
				// Soft-reset-out semantics (withdrawFiltered): a path the
				// current selection rejects but that was previously sent —
				// possible after a runtime knob change tightened the cut
				// (R-037) — must be withdrawn, mirroring what the live
				// ranked sync does when a path falls out of the cut.
				if o.withdrawFiltered && !fp.IsWithdraw && peer.hasPathAlreadyBeenSent(fp) {
					e.paths = append(e.paths, fp.Clone(true))
				}
				e.setMaxFiltered = append(e.setMaxFiltered, fp)
				continue
			}
			e.unsetMaxFiltered = append(e.unsetMaxFiltered, fp)
		}
		if o.dropWithdraws && fp.IsWithdraw {
			continue
		}
		announce = append(announce, fp)
	}
	e.paths = append(e.paths, announce...)
	if !haveKey {
		return e, false
	}
	return e, true
}

// flushExportDumpChunk applies bookkeeping and enqueues one chunk, dropping
// destinations live propagation has claimed since the dump started. The
// dirty check, flag application, updateRoutes and enqueue are atomic under
// the dump mutex so they order cleanly against markExportDumpDirty and
// abortExportDump. Returns sent path count and false when the dump has been
// aborted.
func (s *BgpServer) flushExportDumpChunk(peer *peer, gen uint64, entries []exportDumpChunkEntry, eors []*table.Path) (int, int, bool) {
	d := &peer.dump
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.gen != gen {
		return 0, 0, false
	}
	skipped := 0
	var paths []*table.Path
	for _, e := range entries {
		if _, dirty := d.dirty[e.key]; dirty {
			skipped++
			continue
		}
		for _, p := range e.setMaxFiltered {
			peer.setPathSendMaxFiltered(p)
		}
		for _, p := range e.unsetMaxFiltered {
			peer.unsetPathSendMaxFiltered(p)
		}
		paths = append(paths, e.paths...)
	}
	paths = append(paths, eors...)
	if len(paths) == 0 {
		return 0, skipped, true
	}
	peer.updateRoutes(paths...)
	sendfsmOutgoingMsg(peer, paths)
	return len(paths), skipped, true
}

// hasExportDumpInFlight reports whether a dump walk is currently running.
// The R-230 never-advertised withdraw suppression must stand down while one
// is: the walk flushes from a snapshot older than the live withdraw, and the
// only thing that stops a stale snapshot entry from re-announcing the
// withdrawn path is the live delta claiming the destination dirty — which a
// suppressed (never-enqueued) withdraw would not do. Taking d.mu here also
// orders the check after the final flush's bookkeeping (flushExportDumpChunk
// holds d.mu across updateRoutes), so "no dump in flight" guarantees the
// sent bits the suppression reads already reflect the whole dump.
func (peer *peer) hasExportDumpInFlight() bool {
	d := &peer.dump
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.inflight) > 0
}

// finishExportDump closes out a completed walk: live propagation stops
// paying the dirty-marking cost and the inflight family debt is cleared.
func (peer *peer) finishExportDump(gen uint64) {
	d := &peer.dump
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.gen != gen {
		return
	}
	d.dirty = nil
	d.inflight = nil
	d.inflightWithdrawFiltered = false
	d.inflightDropWithdraws = false
}

// runExportDump is the per-peer dump goroutine.
func (s *BgpServer) runExportDump(peer *peer, o exportDumpOpts, gen uint64) {
	logger := peer.fsm.logger
	start := time.Now()

	// Never snapshot before the FSM loop stores the ESTABLISHED state:
	// handleFSMMessage's establish callback runs before fsm.state.Store, and
	// until the store lands live propagation skips the peer (needToAdvertise
	// false), so a pre-store snapshot would silently lose every update in
	// that window. Checking the live state here (instead of a per-site
	// opt-in flag) also covers a dump that supersedes an establish dump
	// mid-window — e.g. another peer's GR sync-finished loop hitting this
	// peer during its establish callback. Non-establish sites only run for
	// established peers, so this is a no-op for them; a peer that never
	// establishes is unwound by the PeerDown/stopFSM generation bump.
	for peer.State() != bgp.BGP_FSM_ESTABLISHED {
		if peer.exportDumpAborted(gen) {
			return
		}
		time.Sleep(exportDumpEstablishPoll)
	}
	// Re-check after the wait: a session flap can satisfy the state check
	// with the *new* session while this walk's generation is already stale —
	// nothing wrong would reach the wire (every flush re-checks), but the
	// snapshot burst is worth skipping.
	if peer.exportDumpAborted(gen) {
		return
	}

	snap := s.snapshotExportDump(peer, o.families)

	totalDests := 0
	for _, fam := range snap {
		totalDests += len(fam.dests)
	}
	logger.Info("export dump started",
		slog.Any("Families", o.families),
		slog.Int("Destinations", totalDests),
		slog.Duration("SnapshotDuration", time.Since(start)))

	sentPaths, skippedDirty, chunks := 0, 0, 0
	var entries []exportDumpChunkEntry
	pending := 0

	abort := func() {
		logger.Info("export dump aborted",
			slog.Any("Families", o.families),
			slog.Int("SentPaths", sentPaths),
			slog.Int("Chunks", chunks),
			slog.Duration("Elapsed", time.Since(start)))
	}
	flush := func(eors []*table.Path) bool {
		sent, skipped, ok := s.flushExportDumpChunk(peer, gen, entries, eors)
		if !ok {
			return false
		}
		if sent > 0 {
			chunks++
		}
		sentPaths += sent
		skippedDirty += skipped
		entries = entries[:0]
		pending = 0
		// Backpressure: bound the outgoing queue so the dump's memory is
		// a few chunks, not the full export set, when the socket is slow.
		for peer.fsm.outgoingCh.Len() > exportDumpQueueHighWater {
			if peer.exportDumpAborted(gen) {
				return false
			}
			time.Sleep(exportDumpBackpressurePoll)
		}
		return true
	}

	sinceCheck := 0
	for _, fam := range snap {
		for _, dd := range fam.dests {
			sinceCheck++
			if sinceCheck >= exportDumpAbortCheckDests {
				sinceCheck = 0
				if peer.exportDumpAborted(gen) {
					abort()
					return
				}
			}
			entry, ok := s.evalExportDumpDest(peer, fam, dd, o)
			if !ok {
				continue
			}
			entries = append(entries, entry)
			pending += len(entry.paths)
			if pending >= exportDumpChunkPaths {
				if !flush(nil) {
					abort()
					return
				}
			}
		}
	}

	// EORs ride with the final chunk (upstream framing: dump paths and EOR
	// in one message), per the upstream rule: GR-enabled sessions get EORs
	// for every dumped family, and the RTC family always gets one (RFC 4684
	// §6 initial-exchange hint).
	var eors []*table.Path
	isGREnabled := peer.isGracefulRestartEnabled()
	for _, family := range o.families {
		if isGREnabled || family == bgp.RF_RTC_UC {
			eors = append(eors, table.NewEOR(family))
		}
	}
	if !flush(eors) {
		abort()
		return
	}

	peer.finishExportDump(gen)
	logger.Info("export dump finished",
		slog.Any("Families", o.families),
		slog.Int("Destinations", totalDests),
		slog.Int("SentPaths", sentPaths),
		slog.Int("Chunks", chunks),
		slog.Int("DirtySkipped", skippedDirty),
		slog.Duration("Elapsed", time.Since(start)))
}
