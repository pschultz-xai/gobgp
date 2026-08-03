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

// R-037 bucket-aware ADD-PATH export, end to end: with lowest-igp-max set,
// the exported set is the best location-metric bucket (full-tie
// equivalence) capped at lowest-igp-max, padded to min-paths with
// next-ranked paths, under the SendMax ceiling — across incremental
// updates, the establishment dump, withdraw backfill, and WouldExport.

import (
	"context"
	"net/netip"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBucketExportBestBucketOnlyIncremental pins the motivating scenario:
// four candidates, two at the best metric and two at a worse metric, all
// other attributes identical. Flat SendMax=4 would export all four; the
// bucket cut must export exactly the two best-metric paths.
func TestBucketExportBestBucketOnlyIncremental(t *testing.T) {
	mountLocationMetricTable(t, map[uint32]uint32{
		10: 100,
		20: 100,
		30: 200,
		40: 200,
	})

	pod, router := startAddPathsExportPair(t, oc.AddPathsConfig{
		SendMax:      4,
		LowestIgpMax: 4,
		MinPaths:     2,
	})

	// Worst-first injection so ranked order is not arrival order.
	injectLocationCandidate(t, pod, 40, 1)
	injectLocationCandidate(t, pod, 30, 2)
	injectLocationCandidate(t, pod, 20, 3)
	injectLocationCandidate(t, pod, 10, 4)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		ids := receivedLocationIDs(c, router)
		assert.ElementsMatch(c, []uint32{10, 20}, ids,
			"only the best location-metric bucket may be exported")
	}, 10*time.Second, 100*time.Millisecond)
}

// TestBucketExportFloorFillsFromNextRanked pins the min-paths floor: a
// one-path best bucket is padded with the next-ranked path so the router
// keeps a pre-programmed backup.
func TestBucketExportFloorFillsFromNextRanked(t *testing.T) {
	mountLocationMetricTable(t, map[uint32]uint32{
		10: 100,
		30: 200,
		40: 300,
	})

	pod, router := startAddPathsExportPair(t, oc.AddPathsConfig{
		SendMax:      4,
		LowestIgpMax: 4,
		MinPaths:     2,
	})

	injectLocationCandidate(t, pod, 40, 1)
	injectLocationCandidate(t, pod, 30, 2)
	injectLocationCandidate(t, pod, 10, 3)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		ids := receivedLocationIDs(c, router)
		assert.ElementsMatch(c, []uint32{10, 30}, ids,
			"thin bucket must be padded to min-paths with the next-ranked path")
	}, 10*time.Second, 100*time.Millisecond)
}

// TestBucketExportBucketCapAppliesInsideBucket pins lowest-igp-max as a cap
// within the bucket: three same-metric candidates with a cap of two export
// exactly two of them.
func TestBucketExportBucketCapAppliesInsideBucket(t *testing.T) {
	mountLocationMetricTable(t, map[uint32]uint32{
		10: 100,
		20: 100,
		30: 100,
	})

	pod, router := startAddPathsExportPair(t, oc.AddPathsConfig{
		SendMax:      4,
		LowestIgpMax: 2,
		MinPaths:     2,
	})

	injectLocationCandidate(t, pod, 10, 1)
	injectLocationCandidate(t, pod, 20, 2)
	injectLocationCandidate(t, pod, 30, 3)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		ids := receivedLocationIDs(c, router)
		assert.Len(c, ids, 2, "bucket cap must hold inside a same-metric bucket")
		assert.Subset(c, []uint32{10, 20, 30}, ids)
	}, 10*time.Second, 100*time.Millisecond)
}

// TestBucketExportInitialDumpUsesBucketCut pins the session-establishment
// dump (the R-212 async export dump path): a Loc-RIB populated before the
// session comes up must dump the bucket cut, not flat top-SendMax.
func TestBucketExportInitialDumpUsesBucketCut(t *testing.T) {
	mountLocationMetricTable(t, map[uint32]uint32{
		10: 100,
		20: 100,
		30: 200,
		40: 200,
	})

	const asn = 65001
	const listenPort = 10179

	pod := NewBgpServer()
	go pod.Serve()
	err := pod.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        asn,
			RouterId:   "1.1.1.1",
			ListenPort: listenPort,
		},
	})
	require.NoError(t, err)
	t.Cleanup(pod.Stop)

	injectLocationCandidate(t, pod, 40, 1)
	injectLocationCandidate(t, pod, 30, 2)
	injectLocationCandidate(t, pod, 20, 3)
	injectLocationCandidate(t, pod, 10, 4)

	podNeighbor := &oc.Neighbor{
		Config: oc.NeighborConfig{
			NeighborAddress: netip.MustParseAddr("127.0.0.1"),
			PeerAs:          asn,
		},
		Transport: oc.Transport{
			Config: oc.TransportConfig{PassiveMode: true},
		},
		AfiSafis: oc.AfiSafis{
			{
				Config: oc.AfiSafiConfig{
					AfiSafiName: oc.AFI_SAFI_TYPE_IPV4_UNICAST,
					Enabled:     true,
				},
				AddPaths: oc.AddPaths{
					Config: oc.AddPathsConfig{
						SendMax:      4,
						LowestIgpMax: 4,
						MinPaths:     2,
					},
				},
			},
		},
	}
	err = pod.AddPeer(context.Background(), &api.AddPeerRequest{Peer: oc.NewPeerFromConfigStruct(podNeighbor)})
	require.NoError(t, err)

	router := NewBgpServer()
	go router.Serve()
	err = router.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        asn,
			RouterId:   "2.2.2.2",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)
	t.Cleanup(router.Stop)

	routerNeighbor := &oc.Neighbor{
		Config: oc.NeighborConfig{
			NeighborAddress: netip.MustParseAddr("127.0.0.1"),
			PeerAs:          asn,
		},
		Transport: oc.Transport{
			Config: oc.TransportConfig{RemotePort: listenPort},
		},
		Timers: oc.Timers{
			Config: oc.TimersConfig{
				ConnectRetry:           1,
				IdleHoldTimeAfterReset: 1,
			},
		},
		AfiSafis: oc.AfiSafis{
			{
				Config: oc.AfiSafiConfig{
					AfiSafiName: oc.AFI_SAFI_TYPE_IPV4_UNICAST,
					Enabled:     true,
				},
				AddPaths: oc.AddPaths{
					Config: oc.AddPathsConfig{Receive: true},
				},
			},
		},
	}
	established := newPeerStateWaiter(pod, api.PeerState_SESSION_STATE_ESTABLISHED)
	err = router.AddPeer(context.Background(), &api.AddPeerRequest{Peer: oc.NewPeerFromConfigStruct(routerNeighbor)})
	require.NoError(t, err)
	established.Wait(t, 10*time.Second)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		ids := receivedLocationIDs(c, router)
		assert.ElementsMatch(c, []uint32{10, 20}, ids,
			"establishment dump must apply the bucket cut")
	}, 10*time.Second, 100*time.Millisecond)
}

// TestBucketExportWithdrawRebuildsBucket pins churn semantics: withdrawing
// a bucket member re-runs selection — when the bucket thins below
// min-paths, the floor pulls in the next-ranked path.
func TestBucketExportWithdrawRebuildsBucket(t *testing.T) {
	mountLocationMetricTable(t, map[uint32]uint32{
		10: 100,
		20: 100,
		30: 200,
	})

	pod, router := startAddPathsExportPair(t, oc.AddPathsConfig{
		SendMax:      4,
		LowestIgpMax: 4,
		MinPaths:     2,
	})

	injectLocationCandidate(t, pod, 30, 1)
	injectLocationCandidate(t, pod, 20, 2)
	injectLocationCandidate(t, pod, 10, 3)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		ids := receivedLocationIDs(c, router)
		assert.ElementsMatch(c, []uint32{10, 20}, ids)
	}, 10*time.Second, 100*time.Millisecond)

	// Withdraw the location-10 bucket member (identifier 3). The bucket
	// shrinks to {20}; min-paths 2 must pull in location 30 as backup.
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(lmTestPrefix))
	require.NoError(t, err)
	nexthop, err := bgp.NewPathAttributeNextHop(netip.AddrFrom4([4]byte{10, 0, 0, 3}))
	require.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		nexthop,
		bgp.NewPathAttributeLargeCommunities([]*bgp.LargeCommunity{
			{ASN: lmTestGlobalAdmin, LocalData1: table.LocationLCDimension, LocalData2: 10},
		}),
	}
	apiPath, err := apiutil.NewPath(bgp.RF_IPv4_UC, nlri, false, attrs, time.Now())
	require.NoError(t, err)
	apiPath.Identifier = 3
	err = pod.DeletePath(apiutil.DeletePathRequest{Paths: []*apiutil.Path{mustApi2apiutilPath(apiPath)}})
	require.NoError(t, err)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		ids := receivedLocationIDs(c, router)
		assert.ElementsMatch(c, []uint32{20, 30}, ids,
			"withdraw must re-run bucket selection and floor-fill the backup")
	}, 10*time.Second, 100*time.Millisecond)
}

// TestBucketExportWouldExportMatchesLiveCut pins the D-031 shadow
// evaluator: WouldExport must apply the same bucket cut as the live export
// so shadow diffing sees the production selection shape.
func TestBucketExportWouldExportMatchesLiveCut(t *testing.T) {
	mountLocationMetricTable(t, map[uint32]uint32{
		10: 100,
		20: 100,
		30: 200,
		40: 200,
	})

	pod, router := startAddPathsExportPair(t, oc.AddPathsConfig{
		SendMax:      4,
		LowestIgpMax: 4,
		MinPaths:     2,
	})

	injectLocationCandidate(t, pod, 40, 1)
	injectLocationCandidate(t, pod, 30, 2)
	injectLocationCandidate(t, pod, 20, 3)
	injectLocationCandidate(t, pod, 10, 4)

	// Live cut converges first, so WouldExport evaluates a settled RIB.
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		ids := receivedLocationIDs(c, router)
		assert.ElementsMatch(c, []uint32{10, 20}, ids)
	}, 10*time.Second, 100*time.Millisecond)

	got := []uint32{}
	err := pod.WouldExport(context.Background(), WouldExportRequest{
		PeerAddress: "127.0.0.1",
		Family:      bgp.RF_IPv4_UC,
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
						got = append(got, lc.LocalData2)
					}
				}
			}
		}
	})
	require.NoError(t, err)
	assert.ElementsMatch(t, []uint32{10, 20}, got,
		"WouldExport must mirror the live bucket cut")
}
