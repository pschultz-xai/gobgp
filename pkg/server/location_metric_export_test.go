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

// Spike 1 gate 2 (Flow 3, D-034): a peer-group with AddPaths SendMax =
// edge_export.add_path_max must export the top-N paths in D-014 ranked
// order (location metric included) to an iBGP neighbor — regardless of
// the order in which candidates were injected via the AddPath API.

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

const (
	lmTestGlobalAdmin = uint32(65000)
	lmTestPerspective = uint32(1)
	lmTestPrefix      = "10.99.0.0/24"
)

// mountLocationMetricTable configures the process-global D-014 table and
// restores it when the test finishes.
func mountLocationMetricTable(t *testing.T, destinations map[uint32]uint32) {
	t.Helper()
	table.InstallLocationMetric(&table.LocationMetricTable{
		GlobalAdmin:           lmTestGlobalAdmin,
		PerspectiveLocationID: lmTestPerspective,
		Destinations:          destinations,
	})
	t.Cleanup(table.ResetLocationMetric)
}

// startLocationMetricPair starts the pod-side server (s1, exporter with
// SendMax) and the router-side server (s2, ADD-PATH receiver) as iBGP
// peers, and blocks until the session is established. podOpts apply to the
// pod-side server (e.g. GrpcListenAddress for gRPC-level tests).
func startLocationMetricPair(t *testing.T, sendMax uint8, podOpts ...ServerOption) (pod *BgpServer, router *BgpServer) {
	t.Helper()
	return startAddPathsExportPair(t, oc.AddPathsConfig{SendMax: sendMax}, podOpts...)
}

// startAddPathsExportPair is startLocationMetricPair with the full ADD-PATH
// export selection config on the pod-side neighbor (R-037 bucket knobs
// alongside SendMax).
func startAddPathsExportPair(t *testing.T, addPaths oc.AddPathsConfig, podOpts ...ServerOption) (pod *BgpServer, router *BgpServer) {
	t.Helper()

	const asn = 65001
	const listenPort = 10179

	pod = NewBgpServer(podOpts...)
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

	router = NewBgpServer()
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

	// Pod side: passive iBGP neighbor with the ADD-PATH export selection
	// config (peer-group SendMax compiled from edge_export.add_path_max,
	// plus the R-037 bucket knobs when set).
	podNeighbor := &oc.Neighbor{
		Config: oc.NeighborConfig{
			NeighborAddress: netip.MustParseAddr("127.0.0.1"),
			PeerAs:          asn,
		},
		Transport: oc.Transport{
			Config: oc.TransportConfig{
				PassiveMode: true,
			},
		},
		AfiSafis: oc.AfiSafis{
			{
				Config: oc.AfiSafiConfig{
					AfiSafiName: oc.AFI_SAFI_TYPE_IPV4_UNICAST,
					Enabled:     true,
				},
				AddPaths: oc.AddPaths{
					Config: addPaths,
				},
			},
		},
	}
	err = pod.AddPeer(context.Background(), &api.AddPeerRequest{Peer: oc.NewPeerFromConfigStruct(podNeighbor)})
	require.NoError(t, err)

	// Router side: active iBGP neighbor with ADD-PATH receive.
	routerNeighbor := &oc.Neighbor{
		Config: oc.NeighborConfig{
			NeighborAddress: netip.MustParseAddr("127.0.0.1"),
			PeerAs:          asn,
		},
		Transport: oc.Transport{
			Config: oc.TransportConfig{
				RemotePort: listenPort,
			},
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
					Config: oc.AddPathsConfig{
						Receive: true,
					},
				},
			},
		},
	}

	established := newPeerStateWaiter(pod, api.PeerState_SESSION_STATE_ESTABLISHED)
	err = router.AddPeer(context.Background(), &api.AddPeerRequest{Peer: oc.NewPeerFromConfigStruct(routerNeighbor)})
	require.NoError(t, err)
	established.Wait(t)

	return pod, router
}

// injectLocationCandidate adds one candidate path for lmTestPrefix to the
// pod server via the AddPath API, stamped with the given :40: location LC
// and a unique D-017 identifier.
func injectLocationCandidate(t *testing.T, pod *BgpServer, locationID uint32, identifier uint32) {
	t.Helper()

	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(lmTestPrefix))
	require.NoError(t, err)
	// Distinct next-hops so the paths differ beyond the identifier.
	nexthop, err := bgp.NewPathAttributeNextHop(netip.AddrFrom4([4]byte{10, 0, 0, byte(identifier)}))
	require.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		nexthop,
		bgp.NewPathAttributeLargeCommunities([]*bgp.LargeCommunity{
			{ASN: lmTestGlobalAdmin, LocalData1: table.LocationLCDimension, LocalData2: locationID},
		}),
	}

	apiPath, err := apiutil.NewPath(bgp.RF_IPv4_UC, nlri, false, attrs, time.Now())
	require.NoError(t, err)
	apiPath.Identifier = identifier

	_, err = pod.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{mustApi2apiutilPath(apiPath)}})
	require.NoError(t, err)
}

// receivedLocationIDs lists the :40: location LC of every path currently
// in the router server's global RIB for lmTestPrefix.
func receivedLocationIDs(t assert.TestingT, router *BgpServer) []uint32 {
	ids := []uint32{}
	err := router.ListPath(apiutil.ListPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Family:    bgp.RF_IPv4_UC,
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
	assert.NoError(t, err)
	return ids
}

// TestLocationMetricSendMaxExportsTopRankedIncremental pins the core gate
// 2 flow: candidates injected one at a time into an already-established
// session (the PSA steady state) must leave the router holding exactly
// the SendMax best paths in D-014 ranked order — even though the best
// path was injected last.
func TestLocationMetricSendMaxExportsTopRankedIncremental(t *testing.T) {
	mountLocationMetricTable(t, map[uint32]uint32{
		10: 5,  // best
		20: 10, // second
		30: 20, // must be displaced / never exported
	})

	pod, router := startLocationMetricPair(t, 2)
	_ = router

	// Worst-first injection: arrival order is the inverse of ranked order.
	injectLocationCandidate(t, pod, 30, 1)
	injectLocationCandidate(t, pod, 20, 2)
	injectLocationCandidate(t, pod, 10, 3)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		ids := receivedLocationIDs(c, router)
		assert.ElementsMatch(c, []uint32{10, 20}, ids,
			"router must hold exactly the top-SendMax paths by location metric")
	}, 10*time.Second, 100*time.Millisecond)
}

// TestLocationMetricSendMaxExportsTopRankedInitialDump pins the session
// (re)establishment path: when the Loc-RIB already holds more candidates
// than SendMax before the iBGP session comes up, the initial RIB dump
// must also be capped to the top-SendMax ranked paths.
func TestLocationMetricSendMaxExportsTopRankedInitialDump(t *testing.T) {
	mountLocationMetricTable(t, map[uint32]uint32{
		10: 5,
		20: 10,
		30: 20,
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

	// Loc-RIB is populated before any session exists.
	injectLocationCandidate(t, pod, 30, 1)
	injectLocationCandidate(t, pod, 20, 2)
	injectLocationCandidate(t, pod, 10, 3)

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
					Config: oc.AddPathsConfig{SendMax: 2},
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
	established.Wait(t)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		ids := receivedLocationIDs(c, router)
		assert.ElementsMatch(c, []uint32{10, 20}, ids,
			"initial RIB dump must cap at top-SendMax ranked paths")
	}, 10*time.Second, 100*time.Millisecond)
}

// TestLocationMetricSendMaxBackfillsOnWithdraw pins the churn/replace
// semantics (gate 6 precursor): withdrawing an exported path must
// backfill the freed slot with the next-best ranked candidate.
func TestLocationMetricSendMaxBackfillsOnWithdraw(t *testing.T) {
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
		ids := receivedLocationIDs(c, router)
		assert.ElementsMatch(c, []uint32{10, 20}, ids)
	}, 10*time.Second, 100*time.Millisecond)

	// Withdraw the current best (location 10, identifier 3); location 30
	// must backfill so the router again holds SendMax paths.
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
			"withdrawing an exported path must backfill the next-best ranked candidate")
	}, 10*time.Second, 100*time.Millisecond)
}
