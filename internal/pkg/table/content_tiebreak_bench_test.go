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

// Bendrr R-278 round-2: allocation/latency guards for the content
// tie-break. A D-066 metric reload reSorts every destination, so the
// bottom-of-chain comparator must stay near allocation-free once a path's
// content key is memoized (round-1 review MAJOR-2: the unmemoized
// comparator was 93ns/0 allocs -> 510ns/32 allocs per tied compare and
// 3 -> 10,211 allocs for a 256-tied-path reSort).

import (
	"math/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// benchTiedContentPath mirrors tiedContentPath without the testing.T
// plumbing: source-less, fully tied through every comparator above the
// content tie-break, content-distinct via the COMMUNITIES value.
func benchTiedContentPath(pathID, community uint32) *Path {
	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.99.0.0/24"))
	nh, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.1"))
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
			bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65001}),
		}),
		nh,
		bgp.NewPathAttributeCommunities([]uint32{community}),
	}
	return NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri, ID: pathID}, false, attrs, time.Unix(100, 0), false)
}

// Fully-tied pair: the chain runs to the bottom and the content comparator
// decides. This is the compare the round-1 review measured.
func BenchmarkRankBetterPathContentTie(b *testing.B) {
	p1 := benchTiedContentPath(1, 100)
	p2 := benchTiedContentPath(2, 200)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		rankBetterPath(p1, p2)
	}
}

// Pair decided above the bottom (LOCAL_PREF): pins that the content
// tie-break adds no cost to compares that short-circuit earlier.
func BenchmarkRankBetterPathShortCircuit(b *testing.B) {
	p1 := benchTiedContentPath(1, 100)
	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.99.0.0/24"))
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
			bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65001}),
		}),
		bgp.NewPathAttributeLocalPref(200),
	}
	p2 := NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri, ID: 2}, false, attrs, time.Unix(100, 0), false)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		rankBetterPath(p1, p2)
	}
}

// reSort of a destination holding 256 fully-tied content-distinct paths —
// the D-066 reload shape the round-1 review measured (3 allocs at the
// pre-R-278 baseline).
func BenchmarkReSort256Tied(b *testing.B) {
	paths := make([]*Path, 256)
	for i := range paths {
		paths[i] = benchTiedContentPath(uint32(i+1), uint32(i+1))
	}
	rand.New(rand.NewSource(1)).Shuffle(len(paths), func(i, j int) {
		paths[i], paths[j] = paths[j], paths[i]
	})
	d := newDestination(paths[0].GetNlri(), 0, paths...)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		d.reSort(nil, false)
	}
}

// Cold path: first computation of a path's content key (round-3 MINOR-3
// asked for this to be a stated number — the memoized steady state above
// is what ranking pays; this is the once-per-path warm-up cost).
func BenchmarkContentKeyColdCompute(b *testing.B) {
	p := benchTiedContentPath(1, 100)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		p.contentKey.Store(nil)
		_ = p.contentKeyBytes()
	}
}

// insertSort building a destination of 64 fully-tied paths — the
// incremental Calculate shape.
func BenchmarkInsertSort64Tied(b *testing.B) {
	paths := make([]*Path, 64)
	for i := range paths {
		paths[i] = benchTiedContentPath(uint32(i+1), uint32(i+1))
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		d := newDestination(paths[0].GetNlri(), 0)
		for _, p := range paths {
			d.insertSort(p)
		}
	}
}
