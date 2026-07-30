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

// D-066: the location-metric map reload RPC must validate the new map
// (fail-safe: keep the running map on error), swap it atomically, re-rank
// every destination, and bring each peer's advertised set in sync with the
// new ranked order — announcing promoted paths and withdrawing displaced
// ones — without a session flap or full re-inject.

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/config/oc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startPlainLocationMetricPair is startLocationMetricPair without ADD-PATH:
// the pod exports only the best path to the router.
func startPlainLocationMetricPair(t *testing.T) (pod *BgpServer, router *BgpServer) {
	t.Helper()

	const asn = 65001
	const listenPort = 10179

	pod = NewBgpServer()
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

	podNeighbor := &oc.Neighbor{
		Config: oc.NeighborConfig{
			NeighborAddress: netip.MustParseAddr("127.0.0.1"),
			PeerAs:          asn,
		},
		Transport: oc.Transport{
			Config: oc.TransportConfig{PassiveMode: true},
		},
	}
	err = pod.AddPeer(context.Background(), &api.AddPeerRequest{Peer: oc.NewPeerFromConfigStruct(podNeighbor)})
	require.NoError(t, err)

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
	}
	established := newPeerStateWaiter(pod, api.PeerState_SESSION_STATE_ESTABLISHED)
	err = router.AddPeer(context.Background(), &api.AddPeerRequest{Peer: oc.NewPeerFromConfigStruct(routerNeighbor)})
	require.NoError(t, err)
	established.Wait(t, 10*time.Second)

	return pod, router
}

// writeMetricMap writes a D-014 map file ranking the three test locations
// with the given metrics and returns its path.
func writeMetricMap(t *testing.T, dir string, m10, m20, m30 uint32) string {
	t.Helper()
	p := filepath.Join(dir, "metric.yaml")
	body := fmt.Sprintf(`
global_admin: %d
perspective_location_id: %d
destinations:
  10: %d
  20: %d
  30: %d
`, lmTestGlobalAdmin, lmTestPerspective, m10, m20, m30)
	require.NoError(t, os.WriteFile(p, []byte(body), 0o644))
	return p
}

// TestLocationMetricReloadReRanksAddPathExports is the end-to-end D-066
// pin: an established ADD-PATH SendMax session holding the top-2 ranked
// paths must converge to the new top-2 after a metric-map reload, via
// announce/withdraw only.
func TestLocationMetricReloadReRanksAddPathExports(t *testing.T) {
	dir := t.TempDir()
	mapPath := writeMetricMap(t, dir, 5, 10, 20) // rank: 10, 20, 30
	require.NoError(t, table.LoadLocationMetricFile(mapPath, ""))
	t.Cleanup(table.ResetLocationMetric)

	pod, router := startLocationMetricPair(t, 2)

	injectLocationCandidate(t, pod, 30, 1)
	injectLocationCandidate(t, pod, 20, 2)
	injectLocationCandidate(t, pod, 10, 3)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.ElementsMatch(c, []uint32{10, 20}, receivedLocationIDs(c, router))
	}, 10*time.Second, 100*time.Millisecond)

	// Invert the distances on disk: new rank is 30, 20, 10.
	writeMetricMap(t, dir, 20, 10, 5)

	// Dry run: validates and reports, applies nothing.
	stats, err := pod.ReloadLocationMetric(mapPath, "", true)
	require.NoError(t, err)
	assert.True(t, stats.DryRun)
	assert.True(t, stats.MapChanged)
	assert.Equal(t, uint32(5), table.CurrentLocationMetric().Destinations[10],
		"dry run must not install the new map")

	// Real reload: swap + re-rank + minimal re-export.
	stats, err = pod.ReloadLocationMetric(mapPath, "", false)
	require.NoError(t, err)
	assert.True(t, stats.MapChanged)
	assert.Equal(t, 1, stats.RerankedDestinations)
	assert.GreaterOrEqual(t, stats.RibDestinations, 1)
	assert.Equal(t, 1, stats.AnnouncedPaths, "only the promoted path (30) is announced")
	assert.Equal(t, 1, stats.WithdrawnPaths, "only the displaced path (10) is withdrawn")
	assert.Equal(t, uint32(20), table.CurrentLocationMetric().Destinations[10])

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.ElementsMatch(c, []uint32{20, 30}, receivedLocationIDs(c, router),
			"router must hold the new top-SendMax set after reload")
	}, 10*time.Second, 100*time.Millisecond)

	// Reloading the identical map skips the walk entirely.
	stats, err = pod.ReloadLocationMetric(mapPath, "", false)
	require.NoError(t, err)
	assert.False(t, stats.MapChanged)
	assert.Equal(t, 0, stats.RibDestinations)
}

// TestLocationMetricReloadFailSafe pins the runtime validation posture:
// a broken map on disk must be rejected, keeping the running map and the
// current exports untouched.
func TestLocationMetricReloadFailSafe(t *testing.T) {
	dir := t.TempDir()
	mapPath := writeMetricMap(t, dir, 5, 10, 20)
	require.NoError(t, table.LoadLocationMetricFile(mapPath, ""))
	t.Cleanup(table.ResetLocationMetric)

	pod, router := startLocationMetricPair(t, 2)

	injectLocationCandidate(t, pod, 30, 1)
	injectLocationCandidate(t, pod, 10, 2)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.ElementsMatch(c, []uint32{10, 30}, receivedLocationIDs(c, router))
	}, 10*time.Second, 100*time.Millisecond)

	// Empty destinations — fails validation.
	require.NoError(t, os.WriteFile(mapPath, []byte(fmt.Sprintf(`
global_admin: %d
perspective_location_id: %d
destinations: {}
`, lmTestGlobalAdmin, lmTestPerspective)), 0o644))

	_, err := pod.ReloadLocationMetric(mapPath, "", false)
	require.Error(t, err)

	running := table.CurrentLocationMetric()
	assert.Equal(t, uint32(5), running.Destinations[10], "running map must be kept on validation failure")
	assert.ElementsMatch(t, []uint32{10, 30}, receivedLocationIDs(t, router))
}

// TestLocationMetricReloadPlainPeerBestFlip pins the non-ADD-PATH export
// mode: a plain iBGP peer holding only the best path must see a
// replace-style UPDATE when the reload flips the best.
func TestLocationMetricReloadPlainPeerBestFlip(t *testing.T) {
	dir := t.TempDir()
	mapPath := writeMetricMap(t, dir, 5, 10, 20) // best: location 10
	require.NoError(t, table.LoadLocationMetricFile(mapPath, ""))
	t.Cleanup(table.ResetLocationMetric)

	pod, router := startPlainLocationMetricPair(t)

	injectLocationCandidate(t, pod, 30, 1)
	injectLocationCandidate(t, pod, 10, 2)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.ElementsMatch(c, []uint32{10}, receivedLocationIDs(c, router),
			"plain peer holds only the best path")
	}, 10*time.Second, 100*time.Millisecond)

	writeMetricMap(t, dir, 20, 10, 5) // best: location 30

	stats, err := pod.ReloadLocationMetric(mapPath, "", false)
	require.NoError(t, err)
	assert.True(t, stats.MapChanged)
	assert.Equal(t, 1, stats.RerankedDestinations)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.ElementsMatch(c, []uint32{30}, receivedLocationIDs(c, router),
			"plain peer must converge to the new best after reload")
	}, 10*time.Second, 100*time.Millisecond)
}
