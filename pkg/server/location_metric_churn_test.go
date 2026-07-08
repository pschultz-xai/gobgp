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

// Spike 1 gate 6 (Flow 3, D-034): partial ADD-PATH replace on Loc-RIB
// churn. Gate 2 pinned backfill-on-withdraw; these tests pin the rest of
// the churn matrix against the ranked SendMax export patch:
//
//   - attribute change on an exported path that keeps its rank: the router
//     receives an implicit replace (same ADD-PATH path ID) with the new
//     attributes — membership unchanged, no duplicate path;
//   - attribute change that demotes an exported path below the SendMax
//     cut: the path is withdrawn from the peer and the previously
//     suppressed next-ranked candidate is promoted;
//   - attribute change that promotes a suppressed path into the bundle:
//     the displaced tail path is withdrawn.

import (
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// receivedCommunities lists the standard communities of the router-held
// path for lmTestPrefix stamped with the given :40: location LC.
func receivedCommunities(t assert.TestingT, router *BgpServer, locationID uint32) []uint32 {
	comms := []uint32{}
	err := router.ListPath(apiutil.ListPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Family:    bgp.RF_IPv4_UC,
	}, func(prefix bgp.NLRI, paths []*apiutil.Path) {
		if prefix.String() != lmTestPrefix {
			return
		}
		for _, p := range paths {
			matched := false
			var pathComms []uint32
			for _, attr := range p.Attrs {
				switch a := attr.(type) {
				case *bgp.PathAttributeLargeCommunities:
					for _, lc := range a.Values {
						if lc.ASN == lmTestGlobalAdmin && lc.LocalData1 == table.LocationLCDimension && lc.LocalData2 == locationID {
							matched = true
						}
					}
				case *bgp.PathAttributeCommunities:
					pathComms = a.Value
				}
			}
			if matched {
				comms = append(comms, pathComms...)
			}
		}
	})
	assert.NoError(t, err)
	return comms
}

// TestLocationMetricChurnAttributeReplaceKeepsRank pins the in-place
// replace: re-injecting an exported path (same D-017 identifier) with a
// new attribute that does not change its rank must update the path on the
// router without changing bundle membership or duplicating the path.
func TestLocationMetricChurnAttributeReplaceKeepsRank(t *testing.T) {
	mountLocationMetricTable(t, map[uint32]uint32{
		10: 5,
		20: 10,
		30: 20,
	})

	pod, router := startLocationMetricPair(t, 2)

	injectLocationCandidate(t, pod, 30, 1)
	injectLocationCandidate(t, pod, 20, 2)
	injectLocationCandidate(t, pod, 10, 3)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.ElementsMatch(c, []uint32{10, 20}, receivedLocationIDs(c, router))
	}, 10*time.Second, 100*time.Millisecond)

	// Replace the exported loc-10 path (identifier 3) adding a community;
	// rank is unchanged (same LC, same LOCAL_PREF).
	const marker = uint32(65000)<<16 | 99
	_, err := pod.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{
		locationCandidatePath(t, 10, 3, bgp.NewPathAttributeCommunities([]uint32{marker})),
	}})
	require.NoError(t, err)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Contains(c, receivedCommunities(c, router, 10), marker,
			"router must receive the replaced attributes for the exported path")
		// ElementsMatch doubles as a duplicate check: an ADD-PATH replace
		// that announced a second copy instead would list location 10 twice.
		assert.ElementsMatch(c, []uint32{10, 20}, receivedLocationIDs(c, router),
			"membership must not change on a rank-preserving attribute replace")
	}, 10*time.Second, 100*time.Millisecond)
}

// TestLocationMetricChurnRankChangeSwapsBundle pins demotion and promotion
// through attribute churn: lowering LOCAL_PREF on an exported path must
// withdraw it and promote the suppressed next-ranked candidate; raising it
// back above everything must re-promote it and displace the tail.
func TestLocationMetricChurnRankChangeSwapsBundle(t *testing.T) {
	mountLocationMetricTable(t, map[uint32]uint32{
		10: 5,
		20: 10,
		30: 20,
	})

	pod, router := startLocationMetricPair(t, 2)

	injectLocationCandidate(t, pod, 30, 1)
	injectLocationCandidate(t, pod, 20, 2)
	injectLocationCandidate(t, pod, 10, 3)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.ElementsMatch(c, []uint32{10, 20}, receivedLocationIDs(c, router))
	}, 10*time.Second, 100*time.Millisecond)

	// Demote the exported loc-10 path below the default LOCAL_PREF: it
	// falls below the SendMax cut, the suppressed loc-30 path promotes.
	_, err := pod.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{
		locationCandidatePath(t, 10, 3, bgp.NewPathAttributeLocalPref(50)),
	}})
	require.NoError(t, err)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.ElementsMatch(c, []uint32{20, 30}, receivedLocationIDs(c, router),
			"demoting an exported path must withdraw it and promote the suppressed candidate")
	}, 10*time.Second, 100*time.Millisecond)

	// Promote the demoted path above everything: it re-enters the bundle
	// and the tail (loc 30) is displaced again.
	_, err = pod.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{
		locationCandidatePath(t, 10, 3, bgp.NewPathAttributeLocalPref(300)),
	}})
	require.NoError(t, err)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.ElementsMatch(c, []uint32{10, 20}, receivedLocationIDs(c, router),
			"promoting a suppressed path must re-export it and displace the tail")
	}, 10*time.Second, 100*time.Millisecond)
}
