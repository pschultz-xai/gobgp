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

import (
	"math"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// exportSelection carries the per-peer per-family ADD-PATH export selection
// parameters (Bendrr D-034 flat SendMax + R-037 bucket knobs). The zero
// value means "no selection at all" (plain peer / unlimited).
type exportSelection struct {
	// sendMax is the absolute ceiling on exported paths per destination.
	// 0 means uncapped (upstream semantics).
	sendMax int
	// bucketMax (config lowest-igp-max), when > 0, enables bucket-aware
	// selection: only paths tying with the best path through the
	// location-metric comparator slot count as bucket members, capped at
	// bucketMax.
	bucketMax int
	// minPaths (config min-paths) is the floor: when the bucket admits
	// fewer than minPaths paths, next-ranked non-bucket paths fill up to
	// it. Only meaningful with bucketMax > 0.
	minPaths int
}

// active reports whether per-destination selection bookkeeping (SendMax
// filtered flags) is needed at all.
func (sel exportSelection) active() bool {
	return sel.sendMax > 0 || sel.bucketMax > 0
}

// exportSelection reads the peer's selection parameters for one family.
// Selection applies to ADD-PATH send peers only; for other peers the zero
// value is returned (callers gate on isAddPathSendEnabled as before).
func (peer *peer) exportSelection(family bgp.Family) exportSelection {
	conf := peer.fsm.pConf.ReadOnly()
	for _, a := range conf.AfiSafis {
		if a.State.Family == family {
			return exportSelection{
				sendMax:   int(a.AddPaths.Config.SendMax),
				bucketMax: int(a.AddPaths.Config.LowestIgpMax),
				minPaths:  int(a.AddPaths.Config.MinPaths),
			}
		}
	}
	return exportSelection{}
}

// exportSelector decides, over one destination's export-eligible candidates
// visited in best-path ranked order, which paths belong to the exported
// ADD-PATH set (Bendrr R-037):
//
//   - flat mode (bucketMax == 0): the first sendMax survivors — exactly the
//     D-034 behavior.
//   - bucket mode (bucketMax > 0): survivors tying with the first survivor
//     (the bucket anchor) through the location-metric comparator slot are
//     admitted up to bucketMax; all other survivors — non-tying, or tying
//     after the bucket slots are spent — are admitted only while the total
//     is below minPaths (backup floor). sendMax stays the absolute ceiling.
//
// Because compareByMED's comparability rules make the tie relation
// non-transitive, bucket members are not guaranteed to be a contiguous
// prefix of ranked order; each candidate is tested against the anchor
// independently (see table.EqualThroughLocationMetric).
//
// Naming note: paths this selector rejects are flagged (and reported by
// ListPath) as "send-max-filtered" even when SendMax itself has free slots
// and the rejection came from the bucket cut — the flag name predates
// bucket mode and is kept for API compatibility; read it as "suppressed by
// export selection".
//
// The selector is single-destination, single-pass state; build a fresh one
// per destination.
type exportSelector struct {
	sendMax  int
	bucket   int // remaining bucket slots (flat mode: unused)
	floor    int // remaining floor-fill slots
	bucketed bool
	anchor   *table.Path
	total    int
}

// newExportSelector builds a selector from selection parameters,
// normalizing the knobs: sendMax 0 = uncapped; bucketMax and minPaths are
// clamped to sendMax; minPaths below 1 admits no fillers beyond the bucket.
func newExportSelector(sel exportSelection) exportSelector {
	sendMax := sel.sendMax
	if sendMax <= 0 {
		// SendMax == 0 means "no cap" everywhere in the export paths;
		// ADD-PATH send is only negotiated with SendMax > 0 today, but if
		// that ever changes this must not read as "export nothing".
		sendMax = math.MaxInt
	}
	s := exportSelector{sendMax: sendMax}
	if sel.bucketMax > 0 {
		s.bucketed = true
		s.bucket = min(sel.bucketMax, sendMax)
		s.floor = min(sel.minPaths, sendMax)
	}
	return s
}

// admit decides whether the next export-eligible candidate (in ranked
// order) joins the exported set. Callers must pass the Loc-RIB path (the
// path ranking ran on), not the post-export-policy rewrite, so bucket
// equivalence sees the attributes that produced the ranked order.
//
// The admitted count follows the documented formula
// min(max(min(bucket, lowest_igp_max), min(min_paths, n)), send_max) for
// every knob combination — including degenerate ones the bendrr lint
// forbids (min_paths > lowest_igp_max): a bucket-tying candidate that finds
// the bucket slots spent still counts against the floor, so the floor is
// unconditional.
func (s *exportSelector) admit(p *table.Path) bool {
	if s.exhausted() {
		// Cheap short-circuit before the comparator chain: once the bucket
		// slots are spent and the floor is met (or sendMax is hit), no
		// candidate can be admitted, and the equivalence check below costs
		// a nine-step comparator walk per candidate on the serve loop.
		return false
	}
	if !s.bucketed {
		s.total++
		return true
	}
	if s.anchor == nil {
		// First survivor anchors the bucket; bucketMax >= 1 always admits
		// it, and it also consumes a floor slot.
		s.anchor = p
		s.bucket--
		s.total++
		return true
	}
	if table.EqualThroughLocationMetric(p, s.anchor) && s.bucket > 0 {
		s.bucket--
		s.total++
		return true
	}
	// Floor fill: next-ranked candidates outside the bucket — or inside it
	// once the bucket slots are spent — while the total is below minPaths.
	if s.total < s.floor {
		s.total++
		return true
	}
	return false
}

// exhausted reports that no further candidate can be admitted, allowing
// callers that only need the admitted set (not per-path suppression
// bookkeeping) to stop walking early.
func (s *exportSelector) exhausted() bool {
	if s.total >= s.sendMax {
		return true
	}
	if !s.bucketed {
		return false
	}
	return s.anchor != nil && s.bucket <= 0 && s.total >= s.floor
}
