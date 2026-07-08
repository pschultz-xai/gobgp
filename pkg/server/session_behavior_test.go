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

// Spike 1 contract §3.4: session behavior survey.
//
// Pins the GoBGP behaviors Bendrr Flow 1/2 depend on around peer FSM down
// and graceful restart:
//
//   - speaker_id read-back: GetBgp returns the configured router-id, and
//     the remote peer's state reports it (learned from OPEN) — the PSA's
//     speaker_id sanity check.
//   - Hard peer down (no GR): adj-RIB-in from the downed peer is flushed
//     from the Loc-RIB immediately and withdrawn from other peers, while
//     API-injected paths are untouched (Flow 1 "peer down = bulk
//     withdraw"; Flow 2 isolation).
//   - Graceful down (GR negotiated, TCP-level failure): learned paths are
//     RETAINED (marked stale) and stay exported for the peer-advertised
//     restart time, then flushed when the timer expires without
//     re-establishment. This is the Flow 1 edge case: "peer down" from
//     the PSA's perspective is NOT synonymous with "adj-RIB-in gone" when
//     GR is enabled on router→pod sessions.
//
// Upstream classification (pkg/server/fsm.go established-state handler):
// with GR negotiated, read/write failures (TCP close/RST) and self-sent
// hold-timer-expired NOTIFICATIONs become graceful downs; a received
// NOTIFICATION is graceful only with RFC 8538 notification support;
// admin-down and de-configure are always hard. StopBgp/DeletePeer send
// NOTIFICATIONs, so a clean shutdown of the remote speaker is a hard down
// even when GR is negotiated.

import (
	"context"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSpeakerIDReadBack pins the §3.4 speaker_id check: the configured
// router-id reads back via GetBgp on the local speaker, and shows up as
// the remote router-id in the peer's session state on the other side.
func TestSpeakerIDReadBack(t *testing.T) {
	mountLocationMetricTable(t, map[uint32]uint32{10: 5})

	pod, router := startLocationMetricPair(t, 2)

	rsp, err := pod.GetBgp(context.Background(), &api.GetBgpRequest{})
	require.NoError(t, err)
	assert.Equal(t, "1.1.1.1", rsp.Global.RouterId,
		"GetBgp must read back the configured router-id (speaker_id)")

	// The router's view of the pod peer carries the pod's router-id from
	// the OPEN message.
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		var remoteID string
		err := router.ListPeer(context.Background(), &api.ListPeerRequest{Address: "127.0.0.1"}, func(p *api.Peer) {
			remoteID = p.State.RouterId
		})
		assert.NoError(c, err)
		assert.Equal(c, "1.1.1.1", remoteID,
			"peer state must report the pod's configured router-id")
	}, 10*time.Second, 100*time.Millisecond)

	// And symmetrically, the pod sees the router's router-id.
	var routerID string
	err = pod.ListPeer(context.Background(), &api.ListPeerRequest{Address: "127.0.0.1"}, func(p *api.Peer) {
		routerID = p.State.RouterId
	})
	require.NoError(t, err)
	assert.Equal(t, "2.2.2.2", routerID)
}

// TestPeerDownFlushesLearnedKeepsInjected pins the hard peer-down path:
// when the announcing router goes away without GR, its iBGP-learned paths
// are flushed from the pod's Loc-RIB and withdrawn from other peers, while
// API-injected paths are untouched.
func TestPeerDownFlushesLearnedKeepsInjected(t *testing.T) {
	mountLocationMetricTable(t, map[uint32]uint32{
		20: 10,
		30: 20,
	})

	pod, routerA, routerB := startMixedRibTopology(t, 2)

	// Router A announces the local path; one remote candidate is injected.
	injectLocationCandidate(t, routerA, lmTestPerspective, 1)
	injectLocationCandidate(t, pod, 30, 2)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.ElementsMatch(c, []uint32{lmTestPerspective, 30}, receivedLocationIDs(c, routerB))
	}, 10*time.Second, 100*time.Millisecond)

	// Hard down: StopBgp sends a NOTIFICATION (de-configure), which is a
	// non-graceful down at the pod — GR is not negotiated on this session
	// anyway.
	err := routerA.StopBgp(context.Background(), &api.StopBgpRequest{})
	require.NoError(t, err)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.ElementsMatch(c, []uint32{30}, receivedLocationIDs(c, pod),
			"pod Loc-RIB must flush the downed peer's paths and keep injected ones")
		assert.ElementsMatch(c, []uint32{30}, receivedLocationIDs(c, routerB),
			"the downed peer's path must be withdrawn from other peers")
	}, 10*time.Second, 100*time.Millisecond)
}

// TestGracefulRestartHoldsThenFlushes pins the GR edge case that matters
// for Flow 1: with GR negotiated (forwarding preserved) a TCP-level
// session loss does NOT flush adj-RIB-in — learned paths are retained,
// the peer reports PeerRestarting, and the export to other peers stands.
// Only when the peer-advertised restart time expires without
// re-establishment does the pod flush and withdraw. The PSA cannot treat
// "session down" and "routes gone" as the same event on GR sessions.
func TestGracefulRestartHoldsThenFlushes(t *testing.T) {
	mountLocationMetricTable(t, map[uint32]uint32{
		20: 10,
		30: 20,
	})

	const asn = 65001
	const listenPort = 10181

	afiSafisGR := []*api.AfiSafi{
		{
			Config: &api.AfiSafiConfig{
				Family:  apiutil.ToApiFamily(uint16(bgp.AFI_IP), uint8(bgp.SAFI_UNICAST)),
				Enabled: true,
			},
			MpGracefulRestart: &api.MpGracefulRestart{
				Config: &api.MpGracefulRestartConfig{Enabled: true},
			},
		},
	}

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
	t.Cleanup(func() { pod.StopBgp(context.Background(), &api.StopBgpRequest{}) })

	// Pod neighbor A (::1): iBGP announcer with GR helper role.
	err = pod.AddPeer(context.Background(), &api.AddPeerRequest{Peer: &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "::1",
			PeerAsn:         asn,
		},
		Transport:       &api.Transport{PassiveMode: true},
		GracefulRestart: &api.GracefulRestart{Enabled: true},
		AfiSafis:        afiSafisGR,
	}})
	require.NoError(t, err)

	// Pod neighbor B (127.0.0.1): RR client, ADD-PATH send capped at 2.
	err = pod.AddPeer(context.Background(), &api.AddPeerRequest{Peer: &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "127.0.0.1",
			PeerAsn:         asn,
		},
		Transport:      &api.Transport{PassiveMode: true},
		RouteReflector: &api.RouteReflector{RouteReflectorClient: true},
		AfiSafis: []*api.AfiSafi{
			{
				Config: &api.AfiSafiConfig{
					Family:  apiutil.ToApiFamily(uint16(bgp.AFI_IP), uint8(bgp.SAFI_UNICAST)),
					Enabled: true,
				},
				AddPaths: &api.AddPaths{
					Config: &api.AddPathsConfig{SendMax: 2},
				},
			},
		},
	}})
	require.NoError(t, err)

	// Router A: announces the learned path; advertises a short restart
	// time so the test observes both the hold window and the expiry flush.
	routerA := NewBgpServer()
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

	establishedA := newPeerStateWaiter(routerA, api.PeerState_SESSION_STATE_ESTABLISHED)
	err = routerA.AddPeer(context.Background(), &api.AddPeerRequest{Peer: &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "::1",
			PeerAsn:         asn,
		},
		Transport: &api.Transport{RemotePort: listenPort},
		GracefulRestart: &api.GracefulRestart{
			Enabled:     true,
			RestartTime: 5,
		},
		AfiSafis: afiSafisGR,
		Timers: &api.Timers{
			Config: &api.TimersConfig{
				ConnectRetry:           1,
				IdleHoldTimeAfterReset: 1,
			},
		},
	}})
	require.NoError(t, err)
	establishedA.Wait(t, 10*time.Second)

	// Router B: ADD-PATH receiver.
	routerB := NewBgpServer()
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

	establishedB := newPeerStateWaiter(routerB, api.PeerState_SESSION_STATE_ESTABLISHED)
	err = routerB.AddPeer(context.Background(), &api.AddPeerRequest{Peer: &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "127.0.0.1",
			PeerAsn:         asn,
		},
		Transport: &api.Transport{RemotePort: listenPort},
		AfiSafis: []*api.AfiSafi{
			{
				Config: &api.AfiSafiConfig{
					Family:  apiutil.ToApiFamily(uint16(bgp.AFI_IP), uint8(bgp.SAFI_UNICAST)),
					Enabled: true,
				},
				AddPaths: &api.AddPaths{
					Config: &api.AddPathsConfig{Receive: true},
				},
			},
		},
		Timers: &api.Timers{
			Config: &api.TimersConfig{
				ConnectRetry:           1,
				IdleHoldTimeAfterReset: 1,
			},
		},
	}})
	require.NoError(t, err)
	establishedB.Wait(t, 10*time.Second)

	injectLocationCandidate(t, routerA, lmTestPerspective, 1)
	injectLocationCandidate(t, pod, 30, 2)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.ElementsMatch(c, []uint32{lmTestPerspective, 30}, receivedLocationIDs(c, routerB))
	}, 10*time.Second, 100*time.Millisecond)

	// Graceful down: abrupt TCP close (no NOTIFICATION), which the pod —
	// having negotiated GR — classifies as a graceful restart.
	for _, n := range routerA.neighborMap {
		n.fsm.conn.Close()
	}
	err = routerA.StopBgp(context.Background(), &api.StopBgpRequest{})
	require.NoError(t, err)

	// Hold window: pod reports the peer restarting, and both the pod
	// Loc-RIB and the export toward router B retain the learned path.
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		restarting := false
		grRunning := false
		err := pod.ListPeer(context.Background(), &api.ListPeerRequest{Address: "::1"}, func(p *api.Peer) {
			restarting = p.GracefulRestart.PeerRestarting
			for _, af := range p.AfiSafis {
				if af.MpGracefulRestart.State.Running {
					grRunning = true
				}
			}
		})
		assert.NoError(c, err)
		assert.True(c, restarting, "pod must report the peer as restarting")
		assert.True(c, grRunning, "GR must be running for the preserved family")
	}, 5*time.Second, 50*time.Millisecond)

	assert.ElementsMatch(t, []uint32{lmTestPerspective, 30}, receivedLocationIDs(t, pod),
		"pod Loc-RIB must retain the learned path during the GR hold window")
	assert.ElementsMatch(t, []uint32{lmTestPerspective, 30}, receivedLocationIDs(t, routerB),
		"the export to other peers must stand during the GR hold window")

	// Expiry: the restarting speaker never comes back; after its
	// advertised restart time the pod flushes the stale paths and
	// withdraws them from router B. Injected paths are untouched.
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.ElementsMatch(c, []uint32{30}, receivedLocationIDs(c, pod),
			"pod must flush stale learned paths on GR timer expiry")
		assert.ElementsMatch(c, []uint32{30}, receivedLocationIDs(c, routerB),
			"stale paths must be withdrawn from peers on GR timer expiry")
	}, 20*time.Second, 200*time.Millisecond)
}
