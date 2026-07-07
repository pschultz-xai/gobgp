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

// Spike 1 gates 3-5 (Flow 3 / D-031 shadow mode):
//
//   Gate 3 - export_mode: shadow wire suppress. A reject-all export policy
//     (default-action reject, no statements) on the pod's router-facing
//     peer keeps the iBGP session established while no UPDATEs leave.
//   Gate 4 - would-export evaluator. With reject-all assigned, the fork's
//     WouldExport API simulates the staged active export policy + ranked
//     SendMax against the live Loc-RIB without transmitting; live
//     adj-RIB-out stays empty.
//   Gate 5 - adj-RIB-out read API. In active mode ListPath(ADJ_OUT)
//     reflects the ranked SendMax export set, with displaced paths
//     reported as send-max-filtered.

import (
	"context"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// assignRejectAllExport pins the D-031 stage A wire suppress: a policy
// assignment with no statements and default-action reject on the pod's
// export direction.
func assignRejectAllExport(t *testing.T, pod *BgpServer) {
	t.Helper()
	err := pod.SetPolicyAssignment(context.Background(), &api.SetPolicyAssignmentRequest{
		Assignment: &api.PolicyAssignment{
			Name:          table.GLOBAL_RIB_NAME,
			Direction:     api.PolicyDirection_POLICY_DIRECTION_EXPORT,
			Policies:      []*api.Policy{},
			DefaultAction: api.RouteAction_ROUTE_ACTION_REJECT,
		},
	})
	require.NoError(t, err)
}

// adjOutLocationIDs reads the pod's adj-RIB-out toward the router peer and
// returns location ID -> (policyFiltered, sendMaxFiltered) for lmTestPrefix.
type adjOutFlags struct {
	policyFiltered  bool
	sendMaxFiltered bool
}

func adjOutLocationIDs(t assert.TestingT, pod *BgpServer, enableFiltered bool) map[uint32]adjOutFlags {
	out := map[uint32]adjOutFlags{}
	err := pod.ListPath(apiutil.ListPathRequest{
		TableType:      api.TableType_TABLE_TYPE_ADJ_OUT,
		Name:           "127.0.0.1",
		Family:         bgp.RF_IPv4_UC,
		EnableFiltered: enableFiltered,
	}, func(prefix bgp.NLRI, paths []*apiutil.Path) {
		if prefix.String() != lmTestPrefix {
			return
		}
		for _, p := range paths {
			for _, attr := range p.Attrs {
				lcs, ok := attr.(*bgp.PathAttributeLargeCommunities)
				if !ok {
					continue
				}
				for _, lc := range lcs.Values {
					if lc.ASN == lmTestGlobalAdmin && lc.LocalData1 == table.LocationLCDimension {
						out[lc.LocalData2] = adjOutFlags{
							policyFiltered:  p.Filtered,
							sendMaxFiltered: p.SendMaxFiltered,
						}
					}
				}
			}
		}
	})
	assert.NoError(t, err)
	return out
}

// podSessionEstablished reports whether the pod's router-facing peer is in
// the established state.
func podSessionEstablished(t *testing.T, pod *BgpServer) bool {
	t.Helper()
	established := false
	err := pod.ListPeer(context.Background(), &api.ListPeerRequest{Address: "127.0.0.1"}, func(p *api.Peer) {
		established = p.State.SessionState == api.PeerState_SESSION_STATE_ESTABLISHED
	})
	require.NoError(t, err)
	return established
}

// TestShadowRejectAllExportSuppressesWire pins gate 3: with reject-all
// export assigned, candidates injected into the Loc-RIB never reach the
// router, and the iBGP session stays established the whole time.
func TestShadowRejectAllExportSuppressesWire(t *testing.T) {
	mountLocationMetricTable(t, map[uint32]uint32{
		10: 5,
		20: 10,
		30: 20,
	})

	pod, router := startLocationMetricPair(t, 2)
	assignRejectAllExport(t, pod)

	injectLocationCandidate(t, pod, 30, 1)
	injectLocationCandidate(t, pod, 20, 2)
	injectLocationCandidate(t, pod, 10, 3)

	// Loc-RIB must hold all three candidates (shadow mode still runs
	// best-path selection; only the wire is suppressed).
	count := 0
	err := pod.ListPath(apiutil.ListPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Family:    bgp.RF_IPv4_UC,
	}, func(prefix bgp.NLRI, paths []*apiutil.Path) {
		if prefix.String() == lmTestPrefix {
			count = len(paths)
		}
	})
	require.NoError(t, err)
	assert.Equal(t, 3, count, "Loc-RIB must hold all injected candidates")

	// Give propagation ample time to (incorrectly) deliver anything, then
	// verify nothing left the pod and the session is still up.
	time.Sleep(2 * time.Second)
	assert.Empty(t, receivedLocationIDs(t, router), "no UPDATEs may leave under reject-all export")
	assert.True(t, podSessionEstablished(t, pod), "iBGP session must stay established in shadow mode")
}

// TestShadowWouldExportEvaluatesStagedPolicy pins gate 4: while reject-all
// keeps the live adj-RIB-out empty, WouldExport reports what the staged
// active policy would send - the ranked SendMax set, honoring the staged
// policy's own filters.
func TestShadowWouldExportEvaluatesStagedPolicy(t *testing.T) {
	mountLocationMetricTable(t, map[uint32]uint32{
		10: 5,
		20: 10,
		30: 20,
	})

	pod, router := startLocationMetricPair(t, 2)
	assignRejectAllExport(t, pod)

	injectLocationCandidate(t, pod, 30, 1)
	injectLocationCandidate(t, pod, 20, 2)
	injectLocationCandidate(t, pod, 10, 3)

	time.Sleep(2 * time.Second)
	require.Empty(t, receivedLocationIDs(t, router), "precondition: wire suppressed")

	// Live adj-RIB-out is empty under reject-all (unfiltered view applies
	// the assigned export policy).
	assert.Empty(t, adjOutLocationIDs(t, pod, false), "live adj-RIB-out must be empty under reject-all")

	// The filtered view reports every candidate as policy-filtered.
	flags := adjOutLocationIDs(t, pod, true)
	assert.Len(t, flags, 3)
	for id, f := range flags {
		assert.True(t, f.policyFiltered, "location %d must be reported policy-filtered", id)
	}

	wouldExportIDs := func(policyName string) []uint32 {
		ids := []uint32{}
		err := pod.WouldExport(WouldExportRequest{
			PeerAddress: "127.0.0.1",
			Family:      bgp.RF_IPv4_UC,
			PolicyName:  policyName,
		}, func(prefix bgp.NLRI, paths []*apiutil.Path) {
			if prefix.String() != lmTestPrefix {
				return
			}
			for _, p := range paths {
				for _, attr := range p.Attrs {
					lcs, ok := attr.(*bgp.PathAttributeLargeCommunities)
					if !ok {
						continue
					}
					for _, lc := range lcs.Values {
						if lc.ASN == lmTestGlobalAdmin && lc.LocalData1 == table.LocationLCDimension {
							ids = append(ids, lc.LocalData2)
						}
					}
				}
			}
		})
		require.NoError(t, err)
		return ids
	}

	// No staged policy filters: would-export is the ranked top-SendMax set.
	assert.Equal(t, []uint32{10, 20}, wouldExportIDs(""),
		"would-export must report the ranked top-SendMax set in order")

	// Staged policy that rejects location 10: the slot backfills with the
	// next ranked candidate, still capped at SendMax.
	err := pod.AddDefinedSet(context.Background(), &api.AddDefinedSetRequest{
		DefinedSet: &api.DefinedSet{
			DefinedType: api.DefinedType_DEFINED_TYPE_LARGE_COMMUNITY,
			Name:        "lm-loc10",
			List:        []string{"65000:40:10"},
		},
	})
	require.NoError(t, err)
	err = pod.AddPolicy(context.Background(), &api.AddPolicyRequest{
		Policy: &api.Policy{
			Name: "staged-active",
			Statements: []*api.Statement{
				{
					Name: "reject-loc10",
					Conditions: &api.Conditions{
						LargeCommunitySet: &api.MatchSet{
							Name: "lm-loc10",
							Type: api.MatchSet_TYPE_ANY,
						},
					},
					Actions: &api.Actions{
						RouteAction: api.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
			},
		},
	})
	require.NoError(t, err)

	assert.Equal(t, []uint32{20, 30}, wouldExportIDs("staged-active"),
		"staged policy filters must apply before the SendMax cut")

	// An unknown staged policy must error, not silently accept-all.
	err = pod.WouldExport(WouldExportRequest{
		PeerAddress: "127.0.0.1",
		Family:      bgp.RF_IPv4_UC,
		PolicyName:  "no-such-policy",
	}, func(bgp.NLRI, []*apiutil.Path) {})
	assert.Error(t, err)

	// The simulation must not have leaked anything onto the wire.
	assert.Empty(t, receivedLocationIDs(t, router), "would-export must not transmit")
}

// TestActiveAdjRibOutReadReflectsRankedExport pins gate 5: in active mode
// ListPath(ADJ_OUT) reflects the ranked SendMax export set for ops and the
// D-031 wire-test diff; displaced candidates are reported send-max-filtered.
func TestActiveAdjRibOutReadReflectsRankedExport(t *testing.T) {
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

	// Unfiltered view: exactly the wire set.
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		flags := adjOutLocationIDs(c, pod, false)
		ids := make([]uint32, 0, len(flags))
		for id := range flags {
			ids = append(ids, id)
		}
		assert.ElementsMatch(c, []uint32{10, 20}, ids,
			"adj-RIB-out must reflect the ranked SendMax export set")
	}, 10*time.Second, 100*time.Millisecond)

	// Filtered view: all candidates visible, displaced one flagged.
	flags := adjOutLocationIDs(t, pod, true)
	require.Len(t, flags, 3)
	assert.False(t, flags[10].sendMaxFiltered)
	assert.False(t, flags[20].sendMaxFiltered)
	assert.True(t, flags[30].sendMaxFiltered,
		"the displaced candidate must be reported send-max-filtered")
	for id, f := range flags {
		assert.False(t, f.policyFiltered, "location %d must not be policy-filtered in active mode", id)
	}
}