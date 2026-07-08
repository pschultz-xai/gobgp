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

// Spike 1 gate 1a (D-042): mixed-RIB semantics pin.
//
// Paths injected via the AddPath API have an invalid source address and are
// "locally originated" from GoBGP's perspective, so compareByLocalOrigin
// ranks every injected remote candidate above every iBGP-learned local path
// (after LOCAL_PREF, before AS_PATH / MED / the D-014 location-metric slot).
// D-042 adopts this as deliberate policy — remote-first export curation —
// rather than patching compareByLocalOrigin. These tests exist to fail
// loudly if a future upstream rebase moves compareByLocalOrigin or changes
// the locally-originated classification of API-injected paths:
//
//   1. Remote-first bundle membership: injected remote candidates displace
//      an iBGP-learned local path from the SendMax bundle even when the
//      local path carries the own-location LC (metric 0 — best by D-014).
//   2. Local paths fill leftover SendMax slots when remote candidates are
//      fewer than SendMax, and backfill when a remote candidate withdraws.
//   3. Remote-vs-remote ranking falls through the full chain: LOCAL_PREF
//      dominates the location metric; the metric orders the remainder.
//
// Topology for the mixed-RIB tests: three servers in-process. The pod
// listens on both loopbacks; router A (the "local" path source) peers over
// ::1 and router B (the ADD-PATH export receiver, a route-reflector client
// so iBGP-learned paths reflect to it) peers over 127.0.0.1. Both loopback
// addresses exist by default on macOS and Linux.

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

const mixedRibListenPort = 10180

// startMixedRibTopology starts the pod plus two routers: router A announces
// iBGP-learned ("local") paths into the pod over ::1, router B receives the
// pod's ranked ADD-PATH export over 127.0.0.1 as a route-reflector client.
// Both sessions are established on return.
func startMixedRibTopology(t *testing.T, sendMax uint8) (pod, routerA, routerB *BgpServer) {
	t.Helper()

	const asn = 65001

	pod = NewBgpServer()
	go pod.Serve()
	err := pod.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        asn,
			RouterId:   "1.1.1.1",
			ListenPort: mixedRibListenPort,
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { pod.StopBgp(context.Background(), &api.StopBgpRequest{}) })

	// Router A attachment: plain iBGP over ::1, the source of the
	// iBGP-learned local path.
	podNeighborA := &oc.Neighbor{
		Config: oc.NeighborConfig{
			NeighborAddress: netip.MustParseAddr("::1"),
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
			},
		},
	}
	err = pod.AddPeer(context.Background(), &api.AddPeerRequest{Peer: oc.NewPeerFromConfigStruct(podNeighborA)})
	require.NoError(t, err)

	// Router B attachment: RR client (so iBGP-learned paths reflect to it)
	// with ADD-PATH send capped at sendMax.
	podNeighborB := &oc.Neighbor{
		Config: oc.NeighborConfig{
			NeighborAddress: netip.MustParseAddr("127.0.0.1"),
			PeerAs:          asn,
		},
		RouteReflector: oc.RouteReflector{
			Config: oc.RouteReflectorConfig{RouteReflectorClient: true},
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
					Config: oc.AddPathsConfig{SendMax: sendMax},
				},
			},
		},
	}
	err = pod.AddPeer(context.Background(), &api.AddPeerRequest{Peer: oc.NewPeerFromConfigStruct(podNeighborB)})
	require.NoError(t, err)

	routerA = NewBgpServer()
	go routerA.Serve()
	err = routerA.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        asn,
			RouterId:   "3.3.3.3",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { routerA.StopBgp(context.Background(), &api.StopBgpRequest{}) })

	routerANeighbor := &oc.Neighbor{
		Config: oc.NeighborConfig{
			NeighborAddress: netip.MustParseAddr("::1"),
			PeerAs:          asn,
		},
		Transport: oc.Transport{
			Config: oc.TransportConfig{RemotePort: mixedRibListenPort},
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
			},
		},
	}
	establishedA := newPeerStateWaiter(routerA, api.PeerState_SESSION_STATE_ESTABLISHED)
	err = routerA.AddPeer(context.Background(), &api.AddPeerRequest{Peer: oc.NewPeerFromConfigStruct(routerANeighbor)})
	require.NoError(t, err)
	establishedA.Wait(t, 10*time.Second)

	routerB = NewBgpServer()
	go routerB.Serve()
	err = routerB.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        asn,
			RouterId:   "2.2.2.2",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { routerB.StopBgp(context.Background(), &api.StopBgpRequest{}) })

	routerBNeighbor := &oc.Neighbor{
		Config: oc.NeighborConfig{
			NeighborAddress: netip.MustParseAddr("127.0.0.1"),
			PeerAs:          asn,
		},
		Transport: oc.Transport{
			Config: oc.TransportConfig{RemotePort: mixedRibListenPort},
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
	establishedB := newPeerStateWaiter(routerB, api.PeerState_SESSION_STATE_ESTABLISHED)
	err = routerB.AddPeer(context.Background(), &api.AddPeerRequest{Peer: oc.NewPeerFromConfigStruct(routerBNeighbor)})
	require.NoError(t, err)
	establishedB.Wait(t, 10*time.Second)

	return pod, routerA, routerB
}

// locationCandidateAttrs builds the path attributes for one lmTestPrefix
// candidate: origin, a nexthop derived from the identifier, the :40:
// location LC, plus any extras (e.g. LOCAL_PREF).
func locationCandidateAttrs(t *testing.T, locationID, identifier uint32, extra ...bgp.PathAttributeInterface) []bgp.PathAttributeInterface {
	t.Helper()
	nexthop, err := bgp.NewPathAttributeNextHop(netip.AddrFrom4([4]byte{10, 0, 0, byte(identifier)}))
	require.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		nexthop,
		bgp.NewPathAttributeLargeCommunities([]*bgp.LargeCommunity{
			{ASN: lmTestGlobalAdmin, LocalData1: table.LocationLCDimension, LocalData2: locationID},
		}),
	}
	return append(attrs, extra...)
}

func locationCandidatePath(t *testing.T, locationID, identifier uint32, extra ...bgp.PathAttributeInterface) *apiutil.Path {
	t.Helper()
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(lmTestPrefix))
	require.NoError(t, err)
	apiPath, err := apiutil.NewPath(bgp.RF_IPv4_UC, nlri, false, locationCandidateAttrs(t, locationID, identifier, extra...), time.Now())
	require.NoError(t, err)
	apiPath.Identifier = identifier
	return mustApi2apiutilPath(apiPath)
}

// TestMixedRibRemoteFirstCuration pins the D-042 mixed-RIB bundle
// membership semantics end to end:
//
//   - an iBGP-learned local path fills a leftover SendMax slot while remote
//     candidates are fewer than SendMax;
//   - a newly injected remote candidate displaces the local path from the
//     bundle even though the local path carries the own-location LC
//     (metric 0, best by D-014) — compareByLocalOrigin dominates;
//   - withdrawing a remote candidate backfills the local path.
func TestMixedRibRemoteFirstCuration(t *testing.T) {
	mountLocationMetricTable(t, map[uint32]uint32{
		20: 10,
		30: 20,
	})

	pod, routerA, routerB := startMixedRibTopology(t, 2)

	// Router A announces the "local" path: iBGP-learned at the pod, stamped
	// with the pod's own perspective location (metric 0 — the best possible
	// location metric, which must still lose to remote candidates).
	injectLocationCandidate(t, routerA, lmTestPerspective, 1)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.ElementsMatch(c, []uint32{lmTestPerspective}, receivedLocationIDs(c, routerB),
			"the iBGP-learned local path must reflect to the RR client while slots are free")
	}, 10*time.Second, 100*time.Millisecond)

	// One remote candidate: both fit in SendMax=2 — the local path fills
	// the leftover slot.
	injectLocationCandidate(t, pod, 30, 2)
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.ElementsMatch(c, []uint32{lmTestPerspective, 30}, receivedLocationIDs(c, routerB),
			"local path must fill the leftover SendMax slot alongside the remote candidate")
	}, 10*time.Second, 100*time.Millisecond)

	// Second remote candidate: remote-first curation must displace the
	// local path from the bundle, even though the local path's location
	// metric (0) beats both remote metrics.
	injectLocationCandidate(t, pod, 20, 3)
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.ElementsMatch(c, []uint32{20, 30}, receivedLocationIDs(c, routerB),
			"remote candidates must displace the iBGP-learned local path (D-042 remote-first)")
	}, 10*time.Second, 100*time.Millisecond)

	// Withdraw one remote candidate: the local path must backfill.
	err := pod.DeletePath(apiutil.DeletePathRequest{Paths: []*apiutil.Path{locationCandidatePath(t, 20, 3)}})
	require.NoError(t, err)
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.ElementsMatch(c, []uint32{lmTestPerspective, 30}, receivedLocationIDs(c, routerB),
			"local path must backfill the slot freed by the withdrawn remote candidate")
	}, 10*time.Second, 100*time.Millisecond)
}

// TestMixedRibRemoteVsRemoteFullChain pins that injected-vs-injected
// candidates (equal, invalid sources — compareByLocalOrigin abstains) fall
// through the full comparator chain: LOCAL_PREF dominates the D-014
// location metric, and the metric orders the remainder. With SendMax=2 the
// worst-metric candidate carrying LOCAL_PREF 200 must take a slot, the
// best-metric default-LOCAL_PREF candidate takes the other, and the
// middle-metric candidate is displaced.
func TestMixedRibRemoteVsRemoteFullChain(t *testing.T) {
	mountLocationMetricTable(t, map[uint32]uint32{
		10: 5,
		20: 10,
		30: 20,
	})

	pod, router := startLocationMetricPair(t, 2)

	injectLocationCandidate(t, pod, 10, 1) // metric 5, LOCAL_PREF default 100
	injectLocationCandidate(t, pod, 20, 2) // metric 10, LOCAL_PREF default 100
	// Worst metric but LOCAL_PREF 200: must rank first regardless.
	_, err := pod.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{
		locationCandidatePath(t, 30, 3, bgp.NewPathAttributeLocalPref(200)),
	}})
	require.NoError(t, err)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.ElementsMatch(c, []uint32{30, 10}, receivedLocationIDs(c, router),
			"LOCAL_PREF must dominate the location metric; the metric orders the rest")
	}, 10*time.Second, 100*time.Millisecond)
}
