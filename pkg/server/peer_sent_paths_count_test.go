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

// makeSentCountTestPath builds an IPv4 unicast path for prefix originating
// from a distinct source peer, so multiple paths for the same prefix coexist
// in the RIB and receive distinct add-path localIDs.
func makeSentCountTestPath(t *testing.T, prefix string, src netip.Addr) *table.Path {
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

// insertSentCountTestPaths feeds n same-prefix paths from distinct sources
// through the RIB (allocating localIDs) and returns them.
func insertSentCountTestPaths(t *testing.T, rib *table.TableManager, prefix string, n int) []*table.Path {
	t.Helper()
	paths := make([]*table.Path, 0, n)
	for i := range n {
		src := netip.AddrFrom4([4]byte{10, 1, byte(i >> 8), byte(i)})
		path := makeSentCountTestPath(t, prefix, src)
		require.NotEmpty(t, rib.Update(path))
		paths = append(paths, path)
	}
	return paths
}

func TestSentPathsCountNonAddPath(t *testing.T) {
	rib := table.NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC})
	p := newPeerandInfo(t, 65000, 65001, "10.0.0.1", rib)
	p.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_NONE})
	paths := insertSentCountTestPaths(t, rib, "192.0.2.0/24", 2)
	p1, p2 := paths[0], paths[1]

	require.Zero(t, p.getSentPathsCount(bgp.RF_IPv4_UC))

	// Without add-path send, advertisedPathID is 0 for every path, so the
	// count is destination-scoped: p1 and p2 share one slot.
	p.updateRoutes(p1)
	require.Equal(t, uint64(1), p.getSentPathsCount(bgp.RF_IPv4_UC))

	// Re-advertising the same destination is idempotent.
	p.updateRoutes(p2)
	require.Equal(t, uint64(1), p.getSentPathsCount(bgp.RF_IPv4_UC))

	// Nil paths and EOR markers do not count.
	p.updateRoutes(nil, table.NewEOR(bgp.RF_IPv4_UC))
	require.Equal(t, uint64(1), p.getSentPathsCount(bgp.RF_IPv4_UC))

	// A withdraw for the destination drops the count.
	p.updateRoutes(p1.Clone(true))
	require.Zero(t, p.getSentPathsCount(bgp.RF_IPv4_UC))

	// Withdraws for destinations that were never advertised are no-ops and
	// must not drive the count negative.
	p.updateRoutes(p2.Clone(true))
	require.Zero(t, p.getSentPathsCount(bgp.RF_IPv4_UC))
	p.updateRoutes(p1)
	require.Equal(t, uint64(1), p.getSentPathsCount(bgp.RF_IPv4_UC))

	// Other families are independent.
	require.Zero(t, p.getSentPathsCount(bgp.RF_IPv6_UC))
}

func TestSentPathsCountAddPath(t *testing.T) {
	rib := table.NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC})
	p := newPeerandInfo(t, 65000, 65001, "10.0.0.1", rib)
	p.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_SEND})
	paths := insertSentCountTestPaths(t, rib, "192.0.2.0/24", 3)
	p1, p2, p3 := paths[0], paths[1], paths[2]

	// With add-path send, each localID counts separately.
	p.updateRoutes(p1, p2, p3)
	require.Equal(t, uint64(3), p.getSentPathsCount(bgp.RF_IPv4_UC))

	// Re-advertisement of an already-sent path is idempotent.
	p.updateRoutes(p2)
	require.Equal(t, uint64(3), p.getSentPathsCount(bgp.RF_IPv4_UC))

	// Withdrawing one path (as a clone, matching the real call sites)
	// decrements by exactly one; clones share the original's localID.
	p.updateRoutes(p2.Clone(true))
	require.Equal(t, uint64(2), p.getSentPathsCount(bgp.RF_IPv4_UC))

	// Withdrawing the same path again is a no-op.
	p.updateRoutes(p2.Clone(true))
	require.Equal(t, uint64(2), p.getSentPathsCount(bgp.RF_IPv4_UC))

	// Draining the rest returns the count to zero.
	p.updateRoutes(p1.Clone(true), p3.Clone(true))
	require.Zero(t, p.getSentPathsCount(bgp.RF_IPv4_UC))

	// resetAdvertisedRoutes clears the count together with sentPaths.
	p.updateRoutes(p1, p3)
	require.Equal(t, uint64(2), p.getSentPathsCount(bgp.RF_IPv4_UC))
	p.resetAdvertisedRoutes()
	require.Zero(t, p.getSentPathsCount(bgp.RF_IPv4_UC))
}

// TestListPeerAdvertisedCount verifies that ListPeer with EnableAdvertised
// reports the advertised-route count from the peer's RIB-out bookkeeping
// (paths actually sent) without walking the Loc-RIB, and that it honors
// context cancellation inside the management operation.
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
