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

// Bendrr R-005: batched unary apply verbs. These tests pin the per-item
// partial-failure contract — a malformed or failing item is reported at
// its index while its batch siblings install/withdraw normally — and the
// keyed-delete-only shape of DeletePaths (a batch must never widen into a
// uuid or delete-all clear).

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// batchTestPath builds one API-injectable path for 10.0.<n>.0/24 with the
// given ADD-PATH identifier.
func batchTestPath(t *testing.T, n byte, identifier uint32) *api.Path {
	t.Helper()
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(fmt.Sprintf("10.0.%d.0/24", n)))
	require.NoError(t, err)
	nexthop, err := bgp.NewPathAttributeNextHop(netip.AddrFrom4([4]byte{192, 0, 2, 1}))
	require.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		nexthop,
	}
	apiPath, err := apiutil.NewPath(bgp.RF_IPv4_UC, nlri, false, attrs, time.Now())
	require.NoError(t, err)
	apiPath.Identifier = identifier
	return apiPath
}

// globalRIBPathCount sums the paths currently in the server's IPv4 global
// RIB.
func globalRIBPathCount(t *testing.T, s *BgpServer) int {
	t.Helper()
	n := 0
	err := s.ListPath(apiutil.ListPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Family:    bgp.RF_IPv4_UC,
	}, func(prefix bgp.NLRI, paths []*apiutil.Path) {
		n += len(paths)
	})
	require.NoError(t, err)
	return n
}

// TestAddPathsBatchInstallsAll pins the happy path: one AddPaths call
// installs every item and returns a uuid per index.
func TestAddPathsBatchInstallsAll(t *testing.T) {
	s := runNewServer(t, 65001, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	paths := make([]*apiutil.Path, 0, 4)
	for i := byte(0); i < 4; i++ {
		paths = append(paths, mustApi2apiutilPath(batchTestPath(t, i, uint32(i)+1)))
	}
	resps, err := s.AddPaths(apiutil.AddPathRequest{Paths: paths})
	require.NoError(t, err)
	require.Len(t, resps, 4)
	for i, r := range resps {
		assert.NoError(t, r.Error, "item %d", i)
		assert.NotEqual(t, [16]byte{}, [16]byte(r.UUID), "item %d must carry a uuid", i)
	}
	assert.Equal(t, 4, globalRIBPathCount(t, s))
}

// TestAddPathsPartialFailureIsPerItem pins the partial-failure contract: a
// failing item is reported at its index, its siblings install, and the
// call itself does not error.
func TestAddPathsPartialFailureIsPerItem(t *testing.T) {
	s := runNewServer(t, 65001, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	bad := mustApi2apiutilPath(batchTestPath(t, 1, 2))
	bad.Family = 0 // apiutil2Path rejects an unset family

	resps, err := s.AddPaths(apiutil.AddPathRequest{Paths: []*apiutil.Path{
		mustApi2apiutilPath(batchTestPath(t, 0, 1)),
		bad,
		nil,
		mustApi2apiutilPath(batchTestPath(t, 3, 4)),
	}})
	require.NoError(t, err)
	require.Len(t, resps, 4)
	assert.NoError(t, resps[0].Error)
	assert.Error(t, resps[1].Error, "unset family must fail its own index")
	assert.Error(t, resps[2].Error, "nil path must fail its own index")
	assert.NoError(t, resps[3].Error)
	assert.Equal(t, 2, globalRIBPathCount(t, s), "only the good items may install")
}

// TestAddPathsEmptyBatchIsRequestError pins that an empty batch is a
// request-level error, not an empty success.
func TestAddPathsEmptyBatchIsRequestError(t *testing.T) {
	s := runNewServer(t, 65001, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	_, err := s.AddPaths(apiutil.AddPathRequest{})
	assert.Error(t, err)
	_, err = s.DeletePaths(apiutil.DeletePathsRequest{})
	assert.Error(t, err)
}

// TestDeletePathsBatchRemovesByKey pins the keyed batch withdraw: one
// DeletePaths call removes exactly the requested (prefix, identifier)
// items and leaves the rest.
func TestDeletePathsBatchRemovesByKey(t *testing.T) {
	s := runNewServer(t, 65001, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	paths := make([]*apiutil.Path, 0, 4)
	for i := byte(0); i < 4; i++ {
		paths = append(paths, mustApi2apiutilPath(batchTestPath(t, i, uint32(i)+1)))
	}
	_, err := s.AddPaths(apiutil.AddPathRequest{Paths: paths})
	require.NoError(t, err)
	require.Equal(t, 4, globalRIBPathCount(t, s))

	resps, err := s.DeletePaths(apiutil.DeletePathsRequest{Paths: []*apiutil.Path{
		mustApi2apiutilPath(batchTestPath(t, 0, 1)),
		mustApi2apiutilPath(batchTestPath(t, 2, 3)),
	}})
	require.NoError(t, err)
	require.Len(t, resps, 2)
	assert.NoError(t, resps[0].Error)
	assert.NoError(t, resps[1].Error)
	assert.Equal(t, 2, globalRIBPathCount(t, s))
}

// TestDeletePathsPartialFailureIsPerItem mirrors the AddPaths contract on
// the withdraw side: a bad item errors at its index while the good items
// still withdraw in the same dispatch.
func TestDeletePathsPartialFailureIsPerItem(t *testing.T) {
	s := runNewServer(t, 65001, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	_, err := s.AddPaths(apiutil.AddPathRequest{Paths: []*apiutil.Path{
		mustApi2apiutilPath(batchTestPath(t, 0, 1)),
		mustApi2apiutilPath(batchTestPath(t, 1, 2)),
	}})
	require.NoError(t, err)

	bad := mustApi2apiutilPath(batchTestPath(t, 1, 2))
	bad.Family = 0

	resps, err := s.DeletePaths(apiutil.DeletePathsRequest{Paths: []*apiutil.Path{
		mustApi2apiutilPath(batchTestPath(t, 0, 1)),
		bad,
		nil,
	}})
	require.NoError(t, err)
	require.Len(t, resps, 3)
	assert.NoError(t, resps[0].Error)
	assert.Error(t, resps[1].Error)
	assert.Error(t, resps[2].Error)
	assert.Equal(t, 1, globalRIBPathCount(t, s), "the good item must withdraw despite its failing siblings")
}

// TestGRPCBatchApplyVerbs pins the wire surface: per-item results (uuid on
// success, reason on failure) over a real gRPC connection, empty batches
// as InvalidArgument, and per-RPC deadline semantics — the property that
// distinguishes the batched unary shape from AddPathStream.
func TestGRPCBatchApplyVerbs(t *testing.T) {
	socketDir, err := os.MkdirTemp("", "gobgp-batch-apply-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socketAddr := "unix://" + socketDir + "/gobgp.sock"

	s := NewBgpServer(GrpcListenAddress(socketAddr))
	go s.Serve()
	err = s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 65001, RouterId: "1.1.1.1", ListenPort: -1},
	})
	require.NoError(t, err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	conn, err := grpc.NewClient(socketAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	client := api.NewGoBgpServiceClient(conn)

	// Batch add with one malformed item (nil family caught pre-dispatch).
	addResp, err := client.AddPaths(context.Background(), &api.AddPathsRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Paths: []*api.Path{
			batchTestPath(t, 0, 1),
			{}, // no family, no nlri
			batchTestPath(t, 2, 3),
		},
	})
	require.NoError(t, err)
	require.Len(t, addResp.Results, 3)
	assert.Empty(t, addResp.Results[0].Error)
	assert.NotEmpty(t, addResp.Results[0].Uuid)
	assert.NotEmpty(t, addResp.Results[1].Error)
	assert.Empty(t, addResp.Results[1].Uuid)
	assert.Empty(t, addResp.Results[2].Error)
	assert.NotEmpty(t, addResp.Results[2].Uuid)
	assert.Equal(t, 2, globalRIBPathCount(t, s))

	// Batch keyed delete with one malformed item.
	delResp, err := client.DeletePaths(context.Background(), &api.DeletePathsRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Paths: []*api.Path{
			batchTestPath(t, 0, 1),
			{},
		},
	})
	require.NoError(t, err)
	require.Len(t, delResp.Results, 2)
	assert.Empty(t, delResp.Results[0].Error)
	assert.NotEmpty(t, delResp.Results[1].Error)
	assert.Equal(t, 1, globalRIBPathCount(t, s))

	// Empty batches are request-level InvalidArgument.
	_, err = client.AddPaths(context.Background(), &api.AddPathsRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
	})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = client.DeletePaths(context.Background(), &api.DeletePathsRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
	})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	// Unsupported table type is request-level, too.
	_, err = client.AddPaths(context.Background(), &api.AddPathsRequest{
		TableType: api.TableType_TABLE_TYPE_ADJ_IN,
		Paths:     []*api.Path{batchTestPath(t, 5, 1)},
	})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	// Per-RPC deadline: an expired context fails the whole batch at the
	// client — the inject-wedge defense the unary shape keeps (the reason
	// R-005's original AddPathStream idea was shelved).
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	_, err = client.AddPaths(expired, &api.AddPathsRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Paths:     []*api.Path{batchTestPath(t, 6, 1)},
	})
	assert.Equal(t, codes.DeadlineExceeded, status.Code(err))
	assert.Equal(t, 1, globalRIBPathCount(t, s), "the expired-deadline batch must not have installed")
}
