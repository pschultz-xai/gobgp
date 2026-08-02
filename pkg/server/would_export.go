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

// Bendrr fork (D-031 / Spike 1 gate 4): shadow-mode would-export evaluator.
//
// In export_mode: shadow the assigned export policy on GoBGP→router peer
// groups is reject-all, so nothing reaches the wire and adj-RIB-out is
// empty. The shadow diff still needs to know what *would* leave under the
// staged active export policy. WouldExport answers that: it runs the full
// export pipeline (peer/family gates, attribute rewrite, the named staged
// policy instead of the assigned one, and the D-034 ranked SendMax cap)
// against the current Loc-RIB without transmitting anything and without
// touching per-peer advertised-set bookkeeping.
//
// Scale discipline (same class as the U2 /metrics fix): the serialized
// management loop is held only long enough to resolve the peer and snapshot
// the table's destinations. Policy evaluation — O(Loc-RIB × policy), the
// expensive part — runs OUTSIDE the loop over immutable destination
// snapshots, streaming results through fn as it goes and honoring ctx
// cancellation between destinations. A snapshot of a multi-million-path
// Loc-RIB therefore does not stall applies; the price is point-in-time
// consistency (paths applied after the snapshot are not reflected), which
// is exactly what a membership-based shadow diff (D-042) tolerates.

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// WouldExportRequest asks what the named export policy would send to the
// given established peer if it were the assigned export policy.
type WouldExportRequest struct {
	// PeerAddress selects the neighbor whose export perspective (table ID,
	// AS, ADD-PATH SendMax, attribute rewrite) is simulated.
	PeerAddress string
	Family      bgp.Family
	// PolicyName is the staged active export policy to evaluate instead of
	// the assigned (reject-all in shadow mode) export policy. It must have
	// been defined via AddPolicy. Empty means no policy filtering: every
	// path that passes the structural export gates is reported, still
	// capped at ranked SendMax. Default action for a defined policy whose
	// statements all yield no result is accept.
	PolicyName string
}

// WouldExport evaluates the staged export set for one peer and family. fn is
// called once per destination with the paths that would be advertised, in
// best-path ranked order (D-014 comparator chain), capped at the peer's
// ADD-PATH SendMax when ADD-PATH send is negotiated (D-034). Nothing is sent
// to the peer and no advertised-route state is modified.
//
// fn streams during the evaluation: it must not block for long and must not
// call back into the server. Results reflect the Loc-RIB at the moment the
// destination snapshot was taken; ctx cancellation stops the walk between
// destinations.
func (s *BgpServer) WouldExport(ctx context.Context, r WouldExportRequest, fn func(prefix bgp.NLRI, paths []*apiutil.Path)) error {
	type wouldDest struct {
		nlri       bgp.NLRI
		candidates []*table.Path
	}
	var (
		peer        *peer
		dests       []wouldDest
		addPathSend bool
		sendMax     int
		validate    func(*table.Path) *table.Validation
	)

	// Management-loop phase: resolve the peer, validate the request, and
	// snapshot the table (pointer copies of each destination's ranked
	// path list). No policy evaluation happens here.
	err := s.mgmtOperation(func() error {
		remoteAddr, err := netip.ParseAddr(r.PeerAddress)
		if err != nil {
			return fmt.Errorf("failed to parse address: %v", err)
		}
		p, ok := s.neighborMap[remoteAddr]
		if !ok {
			return fmt.Errorf("neighbor that has %v doesn't exist", r.PeerAddress)
		}
		if p.peerInfo.Load() == nil {
			return fmt.Errorf("neighbor %v has no session information yet", r.PeerAddress)
		}
		if r.PolicyName != "" && !s.policy.HasPolicy(r.PolicyName) {
			return fmt.Errorf("not found policy %s", r.PolicyName)
		}

		tbl, ok := p.localRib.GetTable(r.Family)
		if !ok {
			return fmt.Errorf("address family %s is not configured", r.Family)
		}

		peer = p
		id, as := p.TableID(), p.AS()
		// GetDestinations returns immutable snapshots (shard-locked copy
		// of each knownPathList), so the captured path lists are safe to
		// evaluate without locks below.
		for _, dst := range tbl.GetDestinations() {
			dests = append(dests, wouldDest{
				nlri:       dst.GetNlri(),
				candidates: dst.GetKnownPathList(id, as),
			})
		}
		addPathSend = p.isAddPathSendEnabled(r.Family)
		// ADD-PATH send peers get the ranked SendMax set (0 = unlimited,
		// matching upstream semantics).
		if addPathSend {
			sendMax = int(p.getAddPathSendMax(r.Family))
		}

		// The ROA table carries its own lock (Bendrr R-212), so Validate
		// is safe to call during the off-loop evaluation phase — and using
		// it unconditionally keeps this shadow evaluation identical to the
		// real export path, which always passes roaTable.Validate (an
		// RPKI condition matching NOT_FOUND behaves differently under a
		// nil Validate).
		validate = s.roaTable.Validate
		return nil
	}, true)
	if err != nil {
		return err
	}

	// Evaluation phase, off the management loop. Everything read here is
	// concurrency-safe: the captured path lists come from immutable
	// destination snapshots, peer config reads go through the pConf atomic
	// pointer, peerInfo is an atomic Load, and RoutingPolicy application
	// takes its own read lock.
	for _, dst := range dests {
		if err := ctx.Err(); err != nil {
			return err
		}
		var out []*apiutil.Path
		candidates := dst.candidates
		if !addPathSend && len(candidates) > 1 {
			// A plain peer is only ever offered the current best path;
			// if policy rejects it, the runner-up is not substituted.
			candidates = candidates[:1]
		}
		for _, path := range candidates {
			if sendMax > 0 && len(out) >= sendMax {
				break
			}
			p, options, stop := s.prePolicyFilterpath(peer, path, nil)
			if stop {
				continue
			}
			options.Validate = validate
			p, err := s.policy.ApplyPolicyByName(r.PolicyName, p, options)
			if err != nil {
				return err
			}
			if p = s.postFilterpath(peer, p); p == nil {
				continue
			}
			out = append(out, toPathApiUtil(p))
		}
		if len(out) > 0 {
			fn(dst.nlri, out)
		}
	}
	return nil
}
