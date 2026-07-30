// Bendrr D-062: unit tests for the compact per-peer export bookkeeping
// (advertisedState bitmaps replacing the former sentPaths/sendMaxPathFiltered
// sync.Maps). The assertions encode the documented semantics of the old maps
// so the two implementations can be compared directly.

package server

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// makeAdvTestPath builds an IPv4 unicast path for prefix originating from a
// distinct source peer, so multiple paths for the same prefix coexist in the
// RIB and receive distinct add-path localIDs.
func makeAdvTestPath(t *testing.T, prefix string, src netip.Addr) *table.Path {
	t.Helper()
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
	require.NoError(t, err)
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.0.2.254"))
	require.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
			bgp.NewAs4PathParam(2, []uint32{65001}),
		}),
		nh,
	}
	info := &table.PeerInfo{AS: 65001, LocalAS: 65000, Address: src, ID: src}
	return table.NewPath(bgp.RF_IPv4_UC, info, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
}

// newAdvTestPeer returns a peer whose IPv4 unicast add-path mode is set to
// the given value, backed by the given RIB.
func newAdvTestPeer(t *testing.T, rib *table.TableManager, addPathMode bgp.BGPAddPathMode) *peer {
	t.Helper()
	p := newPeerandInfo(t, 65000, 65001, "10.0.0.1", rib)
	p.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_IPv4_UC: addPathMode})
	return p
}

// insertAdvTestPaths feeds n same-prefix paths from distinct sources through
// the RIB (allocating localIDs) and returns them.
func insertAdvTestPaths(t *testing.T, rib *table.TableManager, prefix string, n int) []*table.Path {
	t.Helper()
	paths := make([]*table.Path, 0, n)
	for i := range n {
		src := netip.AddrFrom4([4]byte{10, 1, byte(i >> 8), byte(i)})
		path := makeAdvTestPath(t, prefix, src)
		require.NotEmpty(t, rib.Update(path))
		paths = append(paths, path)
	}
	return paths
}

func TestAdvertisedStateNonAddPath(t *testing.T) {
	rib := table.NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC})
	p := newAdvTestPeer(t, rib, bgp.BGP_ADD_PATH_NONE)
	paths := insertAdvTestPaths(t, rib, "192.0.2.0/24", 2)
	p1, p2 := paths[0], paths[1]

	require.False(t, p.hasPathAlreadyBeenSent(p1))
	require.Equal(t, uint8(0), p.getRoutesCount(bgp.RF_IPv4_UC, p1.GetPrefix()))

	// Without add-path send, advertisedPathID is 0 for every path, so the
	// sent flag is destination-scoped: advertising p1 marks p2 as sent too.
	p.updateRoutes(p1)
	require.True(t, p.hasPathAlreadyBeenSent(p1))
	require.True(t, p.hasPathAlreadyBeenSent(p2))
	require.Equal(t, uint8(1), p.getRoutesCount(bgp.RF_IPv4_UC, p1.GetPrefix()))
	require.Equal(t, 1, p.advertisedDestinationCount())
	require.Equal(t, uint64(1), p.getSentPathsCount(bgp.RF_IPv4_UC))
	require.Zero(t, p.getSentPathsCount(bgp.RF_IPv6_UC))

	// Re-advertising via another path of the same destination is idempotent.
	p.updateRoutes(p2)
	require.Equal(t, uint8(1), p.getRoutesCount(bgp.RF_IPv4_UC, p1.GetPrefix()))
	require.Equal(t, uint64(1), p.getSentPathsCount(bgp.RF_IPv4_UC))

	// A withdraw for the destination clears the flag and drops the entry.
	p.updateRoutes(p1.Clone(true))
	require.False(t, p.hasPathAlreadyBeenSent(p1))
	require.False(t, p.hasPathAlreadyBeenSent(p2))
	require.Equal(t, uint8(0), p.getRoutesCount(bgp.RF_IPv4_UC, p1.GetPrefix()))
	require.Empty(t, p.advRoutes)
	require.Zero(t, p.getSentPathsCount(bgp.RF_IPv4_UC))

	// EOR and nil paths are ignored, and withdraws for unknown destinations
	// are no-ops (the old map deleted from an absent entry); none of them
	// may drive the sent-path count negative.
	p.updateRoutes(nil, table.NewEOR(bgp.RF_IPv4_UC), p2.Clone(true))
	require.Empty(t, p.advRoutes)
	require.Zero(t, p.getSentPathsCount(bgp.RF_IPv4_UC))
	p.updateRoutes(p1)
	require.Equal(t, uint64(1), p.getSentPathsCount(bgp.RF_IPv4_UC))
}

func TestAdvertisedStateAddPath(t *testing.T) {
	rib := table.NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC})
	p := newAdvTestPeer(t, rib, bgp.BGP_ADD_PATH_SEND)
	paths := insertAdvTestPaths(t, rib, "192.0.2.0/24", 3)
	p1, p2, p3 := paths[0], paths[1], paths[2]

	// The RIB allocated distinct non-zero localIDs.
	seen := map[uint32]bool{}
	for _, path := range paths {
		require.NotZero(t, path.LocalID())
		require.False(t, seen[path.LocalID()])
		seen[path.LocalID()] = true
	}

	p.updateRoutes(p1, p2, p3)
	for _, path := range paths {
		require.True(t, p.hasPathAlreadyBeenSent(path))
	}
	require.Equal(t, uint8(3), p.getRoutesCount(bgp.RF_IPv4_UC, p1.GetPrefix()))
	require.Equal(t, 1, p.advertisedDestinationCount())
	require.Equal(t, uint64(3), p.getSentPathsCount(bgp.RF_IPv4_UC))

	// Withdrawing one path (as a clone, matching the real call sites) clears
	// only that path's flag; clones share the original's localID.
	p.updateRoutes(p2.Clone(true))
	require.True(t, p.hasPathAlreadyBeenSent(p1))
	require.False(t, p.hasPathAlreadyBeenSent(p2))
	require.True(t, p.hasPathAlreadyBeenSent(p3))
	require.Equal(t, uint8(2), p.getRoutesCount(bgp.RF_IPv4_UC, p1.GetPrefix()))
	require.Equal(t, uint64(2), p.getSentPathsCount(bgp.RF_IPv4_UC))

	// SendMax-filtered flags are per path and independent of the sent flags.
	require.False(t, p.isPathSendMaxFiltered(p3))
	p.setPathSendMaxFiltered(p3)
	require.True(t, p.isPathSendMaxFiltered(p3))
	require.False(t, p.isPathSendMaxFiltered(p1))
	require.True(t, p.hasPathAlreadyBeenSent(p3))

	// unset reports whether the flag was previously set (old map semantics:
	// Load-then-Delete).
	require.True(t, p.unsetPathSendMaxFiltered(p3))
	require.False(t, p.unsetPathSendMaxFiltered(p3))
	require.False(t, p.isPathSendMaxFiltered(p3))

	// Draining all state removes the destination entry entirely.
	p.updateRoutes(p1.Clone(true), p3.Clone(true))
	require.Equal(t, uint8(0), p.getRoutesCount(bgp.RF_IPv4_UC, p1.GetPrefix()))
	require.Empty(t, p.advRoutes)
	require.Empty(t, p.advOverflow)
	require.Zero(t, p.getSentPathsCount(bgp.RF_IPv4_UC))

	// resetAdvertisedRoutes clears everything at once.
	p.updateRoutes(p1)
	p.setPathSendMaxFiltered(p2)
	p.resetAdvertisedRoutes()
	require.False(t, p.hasPathAlreadyBeenSent(p1))
	require.False(t, p.isPathSendMaxFiltered(p2))
	require.Empty(t, p.advRoutes)
	require.Zero(t, p.getSentPathsCount(bgp.RF_IPv4_UC))
}

// TestAdvertisedStateOverflow exercises destinations with more than
// advInlineIDs-1 concurrent paths (localIDs >= 64 spill into the overflow
// map) and the uint8 clamp of getRoutesCount.
func TestAdvertisedStateOverflow(t *testing.T) {
	const n = 300
	rib := table.NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC})
	p := newAdvTestPeer(t, rib, bgp.BGP_ADD_PATH_SEND)
	paths := insertAdvTestPaths(t, rib, "192.0.2.0/24", n)

	var overflowPath *table.Path
	for _, path := range paths {
		if path.LocalID() >= advInlineIDs {
			overflowPath = path
			break
		}
	}
	require.NotNil(t, overflowPath)

	p.updateRoutes(paths...)
	require.NotEmpty(t, p.advOverflow)
	require.True(t, p.hasPathAlreadyBeenSent(overflowPath))
	require.Equal(t, 1, p.advertisedDestinationCount())
	// The full sent-path count spans inline and overflow bookkeeping and,
	// unlike getRoutesCount, does not clamp at the uint8 maximum.
	require.Equal(t, uint64(n), p.getSentPathsCount(bgp.RF_IPv4_UC))
	// n sent paths clamp to the uint8 maximum, as with len() on the old set.
	require.Equal(t, uint8(255), p.getRoutesCount(bgp.RF_IPv4_UC, overflowPath.GetPrefix()))

	// Filtered flags work above the inline bound too.
	p.setPathSendMaxFiltered(overflowPath)
	require.True(t, p.isPathSendMaxFiltered(overflowPath))
	require.True(t, p.unsetPathSendMaxFiltered(overflowPath))
	require.False(t, p.unsetPathSendMaxFiltered(overflowPath))

	p.updateRoutes(overflowPath.Clone(true))
	require.False(t, p.hasPathAlreadyBeenSent(overflowPath))
	require.Equal(t, uint64(n-1), p.getSentPathsCount(bgp.RF_IPv4_UC))

	// Withdrawing everything drains both maps.
	for _, path := range paths {
		p.updateRoutes(path.Clone(true))
	}
	require.Equal(t, uint8(0), p.getRoutesCount(bgp.RF_IPv4_UC, overflowPath.GetPrefix()))
	require.Empty(t, p.advRoutes)
	require.Empty(t, p.advOverflow)
	require.Zero(t, p.getSentPathsCount(bgp.RF_IPv4_UC))
}

// TestListPeerAdvertisedCount verifies that ListPeer with EnableAdvertised
// reports the advertised-route count from the peer's RIB-out bookkeeping
// (paths actually sent) without walking the Loc-RIB, and that it honors
// context cancellation inside the management operation (Bendrr U2).
func TestListPeerAdvertisedCount(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()

	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65001,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)

	peerAddr := netip.MustParseAddr("10.0.0.1")
	target := newPeerandInfo(t, 65001, 65002, peerAddr.String(), s.globalRib)
	target.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)
	target.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{
		bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_NONE,
	})
	// toConfig serializes the received OPEN of established peers.
	recvOpen, err := bgp.NewBGPOpenMessage(65002, 90, peerAddr, nil)
	require.NoError(t, err)
	target.fsm.recvOpen = recvOpen

	err = s.mgmtOperation(func() error {
		s.neighborMap[peerAddr] = target
		return nil
	}, true)
	require.NoError(t, err)
	t.Cleanup(func() {
		err := s.mgmtOperation(func() error {
			delete(s.neighborMap, peerAddr)
			return nil
		}, false)
		require.NoError(t, err)
		cleanInfiniteChannel(target.fsm.outgoingCh)
		require.NoError(t, s.StopBgp(context.Background(), &api.StopBgpRequest{}))
		s.bfdServer.Stop()
	})

	const pathCount = 16
	for i := range pathCount {
		prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}), 32).String()
		s.propagateUpdate(nil, []*table.Path{makePath(t, prefix, "192.0.2.254", 0)})
	}

	getAdvertised := func(t *testing.T) uint64 {
		t.Helper()
		var advertised uint64
		found := false
		err := s.ListPeer(context.Background(), &api.ListPeerRequest{EnableAdvertised: true}, func(p *api.Peer) {
			for _, afiSafi := range p.GetAfiSafis() {
				state := afiSafi.GetState()
				if state.GetFamily().GetAfi() == api.Family_AFI_IP && state.GetFamily().GetSafi() == api.Family_SAFI_UNICAST {
					advertised = state.GetAdvertised()
					found = true
				}
			}
		})
		require.NoError(t, err)
		require.True(t, found)
		return advertised
	}

	require.Equal(t, uint64(pathCount), getAdvertised(t))

	// Withdrawing one path is reflected without a session reset.
	prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 0, 2, 0}), 32).String()
	s.propagateUpdate(nil, []*table.Path{makePath(t, prefix, "192.0.2.254", 0).Clone(true)})
	require.Equal(t, uint64(pathCount-1), getAdvertised(t))

	// A caller that has gone away is noticed inside the mgmt operation.
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	err = s.ListPeer(cancelled, &api.ListPeerRequest{EnableAdvertised: true}, func(p *api.Peer) {
		t.Error("callback invoked for cancelled context")
	})
	require.ErrorIs(t, err, context.Canceled)
}
