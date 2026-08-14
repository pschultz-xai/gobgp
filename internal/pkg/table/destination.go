// Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
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

package table

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sort"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

var (
	SelectionOptions oc.RouteSelectionOptionsConfig
	UseMultiplePaths oc.UseMultiplePathsConfig
)

type BestPathReason uint8

const (
	BPR_UNKNOWN BestPathReason = iota
	BPR_DISABLED
	BPR_ONLY_PATH
	BPR_REACHABLE_NEXT_HOP
	BPR_HIGHEST_WEIGHT
	BPR_LOCAL_PREF
	BPR_LOCAL_ORIGIN
	BPR_ASPATH
	BPR_ORIGIN
	BPR_MED
	BPR_ASN
	BPR_IGP_COST
	BPR_ROUTER_ID
	BPR_OLDER
	BPR_NON_LLGR_STALE
	BPR_NEIGH_ADDR
)

var BestPathReasonStringMap = map[BestPathReason]string{
	BPR_UNKNOWN:            "Unknown",
	BPR_DISABLED:           "Bestpath selection disabled",
	BPR_ONLY_PATH:          "Only Path",
	BPR_REACHABLE_NEXT_HOP: "Reachable Next Hop",
	BPR_HIGHEST_WEIGHT:     "Highest Weight",
	BPR_LOCAL_PREF:         "Local Pref",
	BPR_LOCAL_ORIGIN:       "Local Origin",
	BPR_ASPATH:             "AS Path",
	BPR_ORIGIN:             "Origin",
	BPR_MED:                "MED",
	BPR_ASN:                "ASN",
	BPR_IGP_COST:           "IGP Cost",
	BPR_ROUTER_ID:          "Router ID",
	BPR_OLDER:              "Older",
	BPR_NON_LLGR_STALE:     "no LLGR Stale",
	BPR_NEIGH_ADDR:         "Neighbor Address",
}

func (r *BestPathReason) String() string {
	return BestPathReasonStringMap[*r]
}

// PeerInfo contains a chunk of peer configuration that is used by table code to determine
// how to handle path attributes. PeerInfo struct can be used both for individual peers
// and peer groups when peer group is in shared policy mode and handles paths in bulk.
//
// It is also used to identify source of path to determine best path, but in that case it
// can only be a peer, not a peer group.
//
// Zero PeerInfo value denotes localSource (paths originated locally) - use localSource
type PeerInfo struct {
	// PeerType: INTERNAL for iBGP peers or EXTERNAL for eBGP peers. Computed from
	// a state based on AS/LocalAS Comparison
	PeerType oc.PeerType

	// AS Number, Address and BGP Identifier (not specified for peer groups) of the remote peer
	AS      uint32
	ID      netip.Addr
	Address netip.Addr

	// Local AS Number, Address and BGP Identifier of local router.
	//
	// AS Number can be overridden using local-as config option on per-peer basis and
	// used for AS_PATH prepending for eBGP peers and for path filtering
	LocalAS      uint32
	LocalID      netip.Addr
	LocalAddress netip.Addr

	// A view of peer/peer group configuration used to compute path attributes correctly
	RouteReflectorClient    bool
	RouteReflectorClusterID netip.Addr
	RouteServerClient       bool
	MultihopTtl             uint8
	Confederation           bool
	RemovePrivateAs         oc.RemovePrivateAsOption

	// PeerGroup contains name for peer group itself if this is PeerInfo for a peer group
	// or the name of peer group this peer belongs to. Used for informational purposes.
	PeerGroup string
}

func (lhs *PeerInfo) Equal(rhs *PeerInfo) bool {
	if lhs == rhs {
		return true
	}

	if rhs == nil {
		return false
	}

	if lhs.AS == rhs.AS && lhs.ID == rhs.ID && lhs.LocalID == rhs.LocalID && lhs.Address == rhs.Address {
		return true
	}
	return false
}

func (i *PeerInfo) String() string {
	const peerTypeUnspecified = oc.PeerType("")
	if i.PeerType == peerTypeUnspecified {
		return "local"
	}

	s := bytes.NewBuffer(make([]byte, 0, 64))
	fmt.Fprintf(s, "{ %s | ", i.Address)
	fmt.Fprintf(s, "as: %d", i.AS)
	fmt.Fprintf(s, ", id: %s", i.ID)
	if i.RouteReflectorClient {
		fmt.Fprintf(s, ", cluster-id: %s", i.RouteReflectorClusterID)
	}
	s.WriteString(" }")
	return s.String()
}

func NewPeerInfo(g *oc.Global, p *oc.Neighbor, AS, localAS uint32, ID, localID netip.Addr, addr, localAddr netip.Addr) *PeerInfo {
	return &PeerInfo{
		PeerType:                p.State.PeerType,
		ID:                      ID,
		AS:                      AS,
		Address:                 addr,
		LocalAS:                 localAS,
		LocalID:                 localID,
		LocalAddress:            localAddr,
		RouteReflectorClient:    p.RouteReflector.Config.RouteReflectorClient,
		RouteReflectorClusterID: p.RouteReflector.State.RouteReflectorClusterId,
		RouteServerClient:       p.RouteServer.Config.RouteServerClient,
		MultihopTtl:             p.EbgpMultihop.Config.MultihopTtl,
		Confederation:           g.IsConfederationMember(AS),
		RemovePrivateAs:         p.State.RemovePrivateAs,
		PeerGroup:               p.Config.PeerGroup,
	}
}

func NewPeerGroupInfo(g *oc.Global, p *oc.PeerGroup) *PeerInfo {
	localAddr := p.Transport.Config.LocalAddress
	if !localAddr.IsValid() {
		localAddr = g.Config.RouterId
	}

	return &PeerInfo{
		PeerType:                p.State.PeerType,
		AS:                      p.Config.PeerAs,
		LocalAS:                 p.Config.LocalAs,
		LocalID:                 g.Config.RouterId,
		LocalAddress:            localAddr,
		RouteReflectorClient:    p.RouteReflector.Config.RouteReflectorClient,
		RouteReflectorClusterID: p.RouteReflector.State.RouteReflectorClusterId,
		RouteServerClient:       p.RouteServer.Config.RouteServerClient,
		MultihopTtl:             p.EbgpMultihop.Config.MultihopTtl,
		Confederation:           g.IsConfederationMember(p.Config.PeerAs),
		RemovePrivateAs:         p.State.RemovePrivateAs,
		PeerGroup:               p.Config.PeerGroupName,
	}
}

// destination represents a BGP destination (prefix) and its associated paths.
//
// LOCKING STRATEGY:
//   - Active destinations (stored in table shards) require the appropriate shard lock
//     to be held when accessing or modifying knownPathList or localIdMap.
//   - Snapshot destinations (created via snapshot()) are immutable copies that can be
//     safely used without locks. They are created while holding the shard lock and
//     contain a copied knownPathList.
//   - Methods document whether they require locks for active destinations. All methods
//     that read knownPathList are safe on snapshots without locks.
//   - Methods that modify state (e.g., Calculate) must NEVER be called on snapshots
//     and ALWAYS require the caller to hold the shard lock.
type destination struct {
	nlri          bgp.NLRI // not mutable
	knownPathList []*Path
	localIdMap    *Bitmap
}

func newDestination(nlri bgp.NLRI, mapSize int, known ...*Path) *destination {
	d := &destination{
		nlri:          nlri,
		knownPathList: known,
		localIdMap:    NewBitmap(mapSize),
	}
	// the id zero means id is not allocated yet.
	if mapSize != 0 {
		d.localIdMap.Flag(0)
	}
	return d
}

// no need to lock here as nlri is not mutable
func (dd *destination) GetNlri() bgp.NLRI {
	return dd.nlri
}

// snapshot returns a stable copy of the destination state.
// Caller must hold the appropriate shard lock when calling this on an active destination.
// The returned snapshot can be used safely without locks.
func (dd *destination) snapshot() *destination {
	return newDestination(dd.nlri, 0, dd.GetAllKnownPathList()...)
}

// GetAllKnownPathList returns a copy of the known path list.
// When called on an active (non-snapshot) destination, caller must hold the appropriate shard lock.
// When called on a snapshot destination, no lock is required as the data is already a stable copy.
func (dd *destination) GetAllKnownPathList() []*Path {
	l := make([]*Path, len(dd.knownPathList))
	copy(l, dd.knownPathList)
	return l
}

func rsFilter(id string, as uint32, path *Path) bool {
	isASLoop := func(as uint32, path *Path) bool {
		return slices.Contains(path.GetAsList(), as)
	}

	return id != GLOBAL_RIB_NAME && (path.GetSource().Address.String() == id || isASLoop(as, path))
}

// GetKnownPathList returns filtered path list.
// When called on an active (non-snapshot) destination, caller must hold the appropriate shard lock.
// When called on a snapshot destination, no lock is required as the data is already a stable copy.
func (dd *destination) GetKnownPathList(id string, as uint32) []*Path {
	list := make([]*Path, 0, len(dd.knownPathList))
	for _, p := range dd.knownPathList {
		if rsFilter(id, as, p) {
			continue
		}
		list = append(list, p)
	}
	return list
}

// GetKnownPathListLength returns the count of known paths.
// When called on an active (non-snapshot) destination, caller must hold the appropriate shard lock.
// When called on a snapshot destination, no lock is required as the data is already a stable copy.
func (dd *destination) GetKnownPathListLength() int {
	return len(dd.knownPathList)
}

func getBestPath(id string, as uint32, pathList []*Path) *Path {
	for _, p := range pathList {
		if rsFilter(id, as, p) {
			continue
		}
		return p
	}
	return nil
}

// GetBestPath returns the best path for the given ID and AS.
// When called on an active (non-snapshot) destination, caller must hold the appropriate shard lock.
// When called on a snapshot destination, no lock is required as the data is already a stable copy.
func (dd *destination) GetBestPath(id string, as uint32) *Path {
	p := getBestPath(id, as, dd.knownPathList)
	if p == nil || p.IsNexthopInvalid {
		return nil
	}
	return p
}

// GetMultiBestPath returns multiple best paths.
// When called on an active (non-snapshot) destination, caller must hold the appropriate shard lock.
// When called on a snapshot destination, no lock is required as the data is already a stable copy.
func (dd *destination) GetMultiBestPath(id string) []*Path {
	return getMultiBestPath(id, dd.knownPathList)
}

// Calculate computes best-path among known paths for this destination.
// Modifies destination's state related to stored paths. Removes withdrawn
// paths from known paths. Also, adds new paths to known paths.
// INTERNAL USE ONLY: Caller MUST hold the appropriate shard lock.
// This method must NEVER be called on snapshot destinations.
func (dest *destination) Calculate(logger *slog.Logger, newPath *Path) (*Update, *Path) {
	oldKnownPathList := make([]*Path, len(dest.knownPathList))
	copy(oldKnownPathList, dest.knownPathList)

	var oldPath *Path
	if newPath.IsWithdraw {
		oldPath = dest.explicitWithdraw(logger, newPath)
		if oldPath != nil && newPath.IsDropped() {
			if id := oldPath.localID; id != 0 {
				dest.localIdMap.Unflag(uint(id))
			}
		}
	} else {
		oldPath = dest.implicitWithdraw(logger, newPath)
		dest.insertSort(newPath)
	}

	for _, path := range dest.knownPathList {
		if path.localID == 0 {
			id, err := dest.localIdMap.FindandSetZeroBit()
			if err != nil {
				dest.localIdMap.Expand()
				id, _ = dest.localIdMap.FindandSetZeroBit()
			}
			path.localID = uint32(id)
		}
	}

	l := make([]*Path, len(dest.knownPathList))
	copy(l, dest.knownPathList)
	return &Update{
		KnownPathList:    l,
		OldKnownPathList: oldKnownPathList,
	}, oldPath
}

// Removes withdrawn paths.
//
// Note:
// We may have disproportionate number of withdraws compared to know paths
// since not all paths get installed into the table due to bgp policy and
// we can receive withdraws for such paths and withdrawals may not be
// stopped by the same policies.
// Returns the old path that was withdrawn.
func (dest *destination) explicitWithdraw(logger *slog.Logger, withdraw *Path) *Path {
	logger.Debug("Removing withdrawals",
		slog.String("Topic", "Table"),
		slog.String("Key", dest.GetNlri().String()))

	// If we have some withdrawals and no know-paths, it means it is safe to
	// delete these withdraws.
	if len(dest.knownPathList) == 0 {
		logger.Debug("Found withdrawals for path(s) that did not get installed",
			slog.String("Topic", "Table"),
			slog.String("Key", dest.GetNlri().String()))
		return nil
	}

	// Match all withdrawals from destination paths.
	isFound := -1
	for i, path := range dest.knownPathList {
		// We have a match if the source and path-id are same.
		if path.EqualBySourceAndPathID(withdraw) {
			isFound = i
			withdraw.localID = path.localID
		}
	}

	// We do not have any match for this withdraw.
	// May be caused by bgp policy if not all paths got installed into the table.
	if isFound == -1 {
		logger.Debug("No matching path for withdraw found, may be path was not installed into table",
			slog.String("Topic", "Table"),
			slog.String("Key", dest.GetNlri().String()),
			slog.String("Path", withdraw.String()))
		return nil
	} else {
		p := dest.knownPathList[isFound]
		dest.knownPathList = append(dest.knownPathList[:isFound], dest.knownPathList[isFound+1:]...)
		return p
	}
}

// Identifies which of known paths are old and removes them.
//
// Known paths will no longer have paths whose new version is present in
// new paths.
// Returns the old path that was withdrawn.
func (dest *destination) implicitWithdraw(logger *slog.Logger, newPath *Path) *Path {
	found := -1
	for i, path := range dest.knownPathList {
		if path.NoImplicitWithdraw() {
			continue
		}
		// Here we just check if source is same and not check if path
		// version num. as newPaths are implicit withdrawal of old
		// paths and when doing RouteRefresh (not EnhancedRouteRefresh)
		// we get same paths again.
		if newPath.EqualBySourceAndPathID(path) {
			logger.Debug("Implicit withdrawal of old path, since we have learned new path from the same peer",
				slog.String("Topic", "Table"),
				slog.String("Key", dest.GetNlri().String()),
				slog.String("Path", path.String()))

			found = i
			newPath.localID = path.localID
			break
		}
	}
	if found != -1 {
		withdrawnPath := dest.knownPathList[found]
		dest.knownPathList = append(dest.knownPathList[:found], dest.knownPathList[found+1:]...)
		return withdrawnPath
	}
	return nil
}

// rankBetterPath runs the full best-path comparator chain over one pair and
// returns the preferred path, or nil on a complete tie. This is the single
// definition of the ranking used by both the incremental insertSort and the
// full reSort a D-066 location-metric reload performs. Since Bendrr R-278
// the chain ends in compareByContent then compareByPathID, so a nil return
// means the two paths carry identical canonical content keys AND the same
// ADD-PATH path identifier. Same-source paths sharing both normally cannot
// coexist — that is the implicit-withdraw identity — but implicitWithdraw
// skips paths flagged NoImplicitWithdraw, so such twins CAN coexist and
// tie completely; they are interchangeable by content and id, so the
// positional fallback in insertSort orders them arbitrarily but
// harmlessly. Beyond that exception, complete ties are confined to
// distinct-source pairs the neighbor-address step could not split.
//
//	Best path processing will involve following steps:
//	1.  Select a path with a reachable next hop.
//	2.  Select the path with the highest weight.
//	3.  If path weights are the same, select the path with the highest
//	local preference value.
//	4.  Prefer locally originated routes (network routes, redistributed
//	routes, or aggregated routes) over received routes.
//	5.  Select the route with the shortest AS-path length.
//	6.  If all paths have the same AS-path length, select the path based
//	on origin: IGP is preferred over EGP; EGP is preferred over
//	Incomplete.
//	7.  If the origins are the same, select the path with lowest MED
//	value.
//	8.  If the paths have the same MED values, select the path learned
//	via EBGP over one learned via IBGP.
//	9.  Select the route with the lowest IGP cost to the next hop.
//	10. Select the route received from the peer with the lowest BGP
//	router ID.
//
//	Assumes paths from NC has source equal to None.
//
// LOCKSTEP (Bendrr R-037): the chain up to the location-metric slot is the
// shared rankPreMetricComparators slice below, ranged by both this function
// and EqualThroughLocationMetric, so the two cannot drift apart on those
// steps. The location-metric slot itself is the one step the two apply
// differently (ranking counts missing-metric lookups for the D-014 alerting
// signal; equivalence uses quiet lookups) — a new comparator must go into
// the shared slice if it belongs above the metric slot, or below the metric
// call in this function only if it is a pure determinism tie-break.
var rankPreMetricComparators = []func(*Path, *Path) *Path{
	compareByLLGRStaleCommunity,
	compareByReachableNexthop,
	compareByLocalPref,
	compareByLocalOrigin,
	compareByASPath,
	compareByOrigin,
	compareByMED,
	compareByASNumber,
}

func rankBetterPath(path1, path2 *Path) *Path {
	for _, cmp := range rankPreMetricComparators {
		if b := cmp(path1, path2); b != nil {
			return b
		}
	}
	if b := compareByLocationMetric(path1, path2); b != nil {
		return b
	}
	if b := compareByAge(path1, path2); b != nil {
		return b
	}
	if b, _ := compareByRouterID(path1, path2); b != nil {
		return b
	}
	if b := compareByNeighborAddress(path1, path2); b != nil {
		return b
	}
	if b := compareByContent(path1, path2); b != nil {
		return b
	}
	return compareByPathID(path1, path2)
}

// EqualThroughLocationMetric reports whether two paths tie at every
// comparator step of rankBetterPath up to and including the D-014
// location-metric slot — i.e. whether they belong to the same "best bucket"
// for bucket-aware ADD-PATH export selection (Bendrr R-037). Paths that are
// equal-through-metric differ only by the pure determinism tie-breaks below
// the metric slot (age, router ID, neighbor address), which carry no
// operational preference.
//
// The pre-metric steps are the shared rankPreMetricComparators slice, so
// they stay in lockstep with rankBetterPath structurally. The metric slot
// uses quiet lookups (no missing-lookup counter bump): equivalence runs
// per candidate per destination per peer on the export hot path, and
// counting there would make the D-014 alerting signal track export volume
// instead of RIB content. Note that compareByMED's comparability rules
// make this relation non-transitive in general (two paths from different
// neighbor AS "tie" on MED without being equal), so callers must not
// assume equal-through-metric paths form a contiguous prefix of a ranked
// list — test each candidate against the bucket anchor.
func EqualThroughLocationMetric(path1, path2 *Path) bool {
	for _, cmp := range rankPreMetricComparators {
		if cmp(path1, path2) != nil {
			return false
		}
	}
	t := CurrentLocationMetric()
	if !t.Enabled() {
		return true
	}
	return t.MetricForPathQuiet(path1) == t.MetricForPathQuiet(path2)
}

func (dest *destination) insertSort(newPath *Path) {
	// Find the correct position for newPath. The slice is assumed to be in
	// descending order: most preferred to least. On a complete tie the new
	// path is inserted before the equal element (matching historical
	// behavior). Since R-278 a complete tie requires identical canonical
	// content key AND identical path id (compareByContent +
	// compareByPathID) — reachable for same-source paths only through the
	// NoImplicitWithdraw flag (implicitWithdraw skips flagged paths, so
	// key-and-id twins can coexist), otherwise only for distinct-source
	// pairs the neighbor-address step could not split. Either way the tied
	// paths are interchangeable by content and id, so this positional
	// fallback is harmless — not the ordinary path for injected twins.
	insertIdx := sort.Search(len(dest.knownPathList), func(i int) bool {
		return rankBetterPath(newPath, dest.knownPathList[i]) != dest.knownPathList[i]
	})

	// Insert at the found position
	dest.knownPathList = slices.Insert(dest.knownPathList, insertIdx, newPath)
}

// reSort fully re-sorts knownPathList under the current comparator chain
// and reports whether the destination needs re-export. Needed when a global
// comparator input changes out from under already-sorted lists — the D-066
// location-metric map reload — because insertSort relies on the sorted
// invariant for every future incremental update. The sort is stable, so
// paths that tie keep their current relative order.
//
// "Needs re-export" is NOT just "the order moved": bucket-aware export
// selection (Bendrr R-037) keys on metric VALUES via
// EqualThroughLocationMetric, so a reload can change bucket membership —
// and therefore the exported set — without moving the ranked order at all
// (e.g. two tied locations diverging while their relative rank holds).
// oldTbl is the table that was installed before the reload swap; when the
// per-path metric partition differs between oldTbl and the currently
// installed table, the destination is reported changed even if the order
// held, so the reload re-runs export selection for it. tablesDiffer is
// !oldTbl.Equal(CurrentLocationMetric()), computed ONCE by the walk —
// hoisted out of here because the full-map comparison is loop-invariant
// and this runs per destination under the shard write lock (round-2
// review NEW-8).
//
// INTERNAL USE ONLY: caller MUST hold the appropriate shard lock and must
// NEVER call this on snapshot destinations.
func (dest *destination) reSort(oldTbl *LocationMetricTable, tablesDiffer bool) (*Update, bool) {
	oldKnownPathList := make([]*Path, len(dest.knownPathList))
	copy(oldKnownPathList, dest.knownPathList)

	sort.SliceStable(dest.knownPathList, func(i, j int) bool {
		return rankBetterPath(dest.knownPathList[i], dest.knownPathList[j]) == dest.knownPathList[i]
	})

	changed := false
	for i, p := range dest.knownPathList {
		if oldKnownPathList[i] != p {
			changed = true
			break
		}
	}
	if !changed && tablesDiffer && metricPartitionChanged(oldTbl, CurrentLocationMetric(), dest.knownPathList) {
		changed = true
	}
	if !changed {
		return nil, false
	}

	l := make([]*Path, len(dest.knownPathList))
	copy(l, dest.knownPathList)
	return &Update{
		KnownPathList:    l,
		OldKnownPathList: oldKnownPathList,
	}, true
}

// metricPartitionChanged reports whether swapping oldTbl for newTbl changes
// the metric-equality partition of paths — i.e. whether any PAIR of paths
// that tied on metric under one table does not tie under the other. That is
// the only way a location-metric reload can change bucket membership
// (EqualThroughLocationMetric's non-metric steps are table-independent), so
// it is the exact extra re-export trigger reSort needs. Deliberately
// conservative: it ignores whether a differing pair also ties on the
// non-metric steps, so it can report true for destinations whose export set
// is in fact unchanged — the re-export sync is idempotent and emits nothing
// for those. Callers gate on the tables actually differing (reSort's
// tablesDiffer); the loop-invariant oldTbl.Equal check lives in
// ReRankDestinations, not here.
func metricPartitionChanged(oldTbl, newTbl *LocationMetricTable, paths []*Path) bool {
	if len(paths) < 2 {
		return false
	}
	// The partition is unchanged iff old-metric ↔ new-metric is a
	// bijection over the paths: every old-metric class maps to exactly one
	// new-metric class and vice versa.
	fwd := make(map[uint32]uint32, len(paths))
	rev := make(map[uint32]uint32, len(paths))
	for _, p := range paths {
		o, n := oldTbl.MetricForPathQuiet(p), newTbl.MetricForPathQuiet(p)
		if v, ok := fwd[o]; ok && v != n {
			return true
		}
		fwd[o] = n
		if v, ok := rev[n]; ok && v != o {
			return true
		}
		rev[n] = o
	}
	return false
}

type Update struct {
	KnownPathList    []*Path
	OldKnownPathList []*Path
}

// GetMultiBestPathDiff returns multipath delta as update and withdraw lists.
// update includes both newly added and changed paths.
func (u *Update) GetMultiBestPathDiff(id string) (update []*Path, withdraw []*Path) {
	oldM := getMultiBestPath(id, u.OldKnownPathList)
	newM := getMultiBestPath(id, u.KnownPathList)
	if len(oldM) == 0 && len(newM) == 0 {
		return nil, nil
	}

	matchedOld := make([]bool, len(oldM))
	for _, n := range newM {
		match := -1
		for idx, o := range oldM {
			if n.EqualBySourceAndPathID(o) {
				match = idx
				break
			}
		}
		if match == -1 {
			update = append(update, n)
			continue
		}
		matchedOld[match] = true
		if !n.Equal(oldM[match]) {
			update = append(update, n)
		}
	}
	for idx, o := range oldM {
		if !matchedOld[idx] {
			withdraw = append(withdraw, o.Clone(true))
		}
	}
	return update, withdraw
}

func getMultiBestPath(id string, pathList []*Path) []*Path {
	// The path list of destinations in the global RIB are sorted
	// in descending order. One of the criteria for being a better
	// path is that it has a reachable next hop. Technically, if the
	// first path is unreachable, then it's assumed none of them
	// are. Therefore, we return an empty slice.
	if len(pathList) == 0 || len(pathList) > 0 && pathList[0].IsNexthopInvalid {
		// No reachable next hop found, so we return an empty slice.
		return []*Path{}
	}
	best := pathList[0]

	// Attempt to find the first path that is both reachable and worse than the
	// best path. Then return a slice paths from the best to that index.
	index := sort.Search(len(pathList), func(i int) bool {
		return pathList[i].IsNexthopInvalid || pathList[i].Compare(best) != 0
	})
	return pathList[:index]
}

func (u *Update) GetWithdrawnPath() []*Path {
	if len(u.KnownPathList) == len(u.OldKnownPathList) {
		return nil
	}

	l := make([]*Path, 0, len(u.OldKnownPathList))

	for _, p := range u.OldKnownPathList {
		y := func() bool {
			return slices.Contains(u.KnownPathList, p)
		}()
		if !y {
			l = append(l, p.Clone(true))
		}
	}
	return l
}

func (u *Update) GetChanges(id string, as uint32, peerDown bool) (*Path, *Path, []*Path) {
	best, old := func(id string) (*Path, *Path) {
		old := getBestPath(id, as, u.OldKnownPathList)
		best := getBestPath(id, as, u.KnownPathList)
		if best != nil && best.Equal(old) {
			// RFC4684 3.2. Intra-AS VPN Route Distribution
			// When processing RT membership NLRIs received from internal iBGP
			// peers, it is necessary to consider all available iBGP paths for a
			// given RT prefix, for building the outbound route filter, and not just
			// the best path.
			if best.GetFamily() == bgp.RF_RTC_UC {
				return best, old
			}
			// For BGP Nexthop Tracking, checks if the nexthop reachability
			// was changed or not.
			if best.IsNexthopInvalid != old.IsNexthopInvalid {
				// If the nexthop of the best path became unreachable, we need
				// to withdraw that path.
				if best.IsNexthopInvalid {
					return best.Clone(true), old
				}
				return best, old
			}
			return nil, old
		}
		if best == nil || best.IsNexthopInvalid {
			if old == nil || old.IsNexthopInvalid {
				return nil, nil
			}
			if peerDown {
				// withdraws were generated by peer
				// down so paths are not in knowpath
				// or adjin.
				old.IsWithdraw = true
				return old, old
			}
			return old.Clone(true), old
		}
		return best, old
	}(id)

	var multi []*Path

	if id == GLOBAL_RIB_NAME && UseMultiplePaths.Enabled {
		diff := func(lhs, rhs []*Path) bool {
			if len(lhs) != len(rhs) {
				return true
			}
			for idx, l := range lhs {
				if !l.Equal(rhs[idx]) {
					return true
				}
			}
			return false
		}
		oldM := getMultiBestPath(id, u.OldKnownPathList)
		newM := getMultiBestPath(id, u.KnownPathList)
		if diff(oldM, newM) {
			multi = newM
			if len(newM) == 0 {
				multi = []*Path{best}
			}
		}
	}
	return best, old, multi
}

func compareByLLGRStaleCommunity(path1, path2 *Path) *Path {
	p1 := path1.IsLLGRStale()
	p2 := path2.IsLLGRStale()
	if p1 == p2 {
		return nil
	} else if p1 {
		return path2
	}
	return path1
}

func compareByReachableNexthop(path1, path2 *Path) *Path {
	//	Compares given paths and selects best path based on reachable next-hop.
	//
	//	If no path matches this criteria, return nil.
	//	For BGP Nexthop Tracking, evaluates next-hop is validated by IGP.

	if path1.IsNexthopInvalid && !path2.IsNexthopInvalid {
		return path2
	} else if !path1.IsNexthopInvalid && path2.IsNexthopInvalid {
		return path1
	}

	return nil
}

func compareByLocalPref(path1, path2 *Path) *Path {
	//	Selects a path with highest local-preference.
	//
	//	Unlike the weight attribute, which is only relevant to the local
	//	router, local preference is an attribute that routers exchange in the
	//	same AS. Highest local-pref is preferred. If we cannot decide,
	//	we return None.
	//
	//	# Default local-pref values is 100
	localPref1, _ := path1.GetLocalPref()
	localPref2, _ := path2.GetLocalPref()
	// Highest local-preference value is preferred.
	if localPref1 > localPref2 {
		return path1
	} else if localPref1 < localPref2 {
		return path2
	} else {
		return nil
	}
}

func compareByLocalOrigin(path1, path2 *Path) *Path {
	// Select locally originating path as best path.
	// Locally originating routes are network routes, redistributed routes,
	// or aggregated routes.
	// Returns None if given paths have same source.
	//
	// If both paths are from same sources we cannot compare them here.
	if path1.GetSource().Equal(path2.GetSource()) {
		return nil
	}

	// Here we consider prefix from NC as locally originating static route.
	// Hence it is preferred.
	if path1.IsLocal() {
		return path1
	}

	if path2.IsLocal() {
		return path2
	}
	return nil
}

func compareByASPath(path1, path2 *Path) *Path {
	// Calculated the best-paths by comparing as-path lengths.
	//
	// Shortest as-path length is preferred. If both path have same lengths,
	// we return None.
	if SelectionOptions.IgnoreAsPathLength {
		return nil
	}

	l1 := path1.GetAsPathLen()
	l2 := path2.GetAsPathLen()

	if l1 > l2 {
		return path2
	} else if l1 < l2 {
		return path1
	} else {
		return nil
	}
}

func compareByOrigin(path1, path2 *Path) *Path {
	//	Select the best path based on origin attribute.
	//
	//	IGP is preferred over EGP; EGP is preferred over Incomplete.
	//	If both paths have same origin, we return None.

	attribute1 := path1.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	attribute2 := path2.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)

	if attribute1 == nil || attribute2 == nil {
		return nil
	}

	origin1 := attribute1.(*bgp.PathAttributeOrigin).Value
	origin2 := attribute2.(*bgp.PathAttributeOrigin).Value

	// If both paths have same origins
	if origin1 == origin2 {
		return nil
	} else if origin1 < origin2 {
		return path1
	} else {
		return path2
	}
}

func compareByMED(path1, path2 *Path) *Path {
	//	Select the path based with lowest MED value.
	//
	//	If both paths have same MED, return None.
	//	By default, a route that arrives with no MED value is treated as if it
	//	had a MED of 0, the most preferred value.
	//	RFC says lower MED is preferred over higher MED value.
	//  compare MED among not only same AS path but also all path,
	//  like bgp always-compare-med

	isInternal := func() bool { return path1.GetAsPathLen() == 0 && path2.GetAsPathLen() == 0 }()

	isSameAS := func() bool {
		firstAS := func(path *Path) uint32 {
			if asPath := path.GetAsPath(); asPath != nil {
				for _, v := range asPath.Value {
					asList := v.GetAS()
					if len(asList) == 0 {
						continue
					}
					switch v.GetType() {
					case bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET, bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ:
						continue
					}
					return asList[0]
				}
			}
			return 0
		}
		return firstAS(path1) != 0 && firstAS(path1) == firstAS(path2)
	}()

	if SelectionOptions.AlwaysCompareMed || isInternal || isSameAS {
		getMed := func(path *Path) uint32 {
			attribute := path.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
			if attribute == nil {
				return 0
			}
			med := attribute.(*bgp.PathAttributeMultiExitDisc).Value
			return med
		}

		med1 := getMed(path1)
		med2 := getMed(path2)
		if med1 == med2 {
			return nil
		} else if med1 < med2 {
			return path1
		}
		return path2
	} else {
		return nil
	}
}

func compareByASNumber(path1, path2 *Path) *Path {
	//Select the path based on source (iBGP/eBGP) peer.
	//
	//eBGP path is preferred over iBGP. If both paths are from same kind of
	//peers, return None.

	// Path from confederation member should be treated as internal (IBGP learned) path.
	isIBGP1 := path1.GetSource().Confederation || path1.IsIBGP()
	isIBGP2 := path2.GetSource().Confederation || path2.IsIBGP()
	// If one path is from ibgp peer and another is from ebgp peer, take the ebgp path.
	if isIBGP1 != isIBGP2 {
		if isIBGP1 {
			return path2
		}
		return path1
	}

	// If both paths are from ebgp or ibpg peers, we cannot decide.
	return nil
}

func compareByRouterID(path1, path2 *Path) (*Path, error) {
	//	Select the route received from the peer with the lowest BGP router ID.
	//
	//	If both paths are eBGP paths, then we do not do any tie breaking, i.e we do
	//	not pick best-path based on this criteria.
	//	RFC: http://tools.ietf.org/html/rfc5004
	//	We pick best path between two iBGP paths as usual.

	// If both paths are from NC we have same router Id, hence cannot compare.
	if path1.IsLocal() && path2.IsLocal() {
		return nil, nil
	}

	// If both paths are from eBGP peers, then according to RFC we need
	// not tie break using router id.
	if !SelectionOptions.ExternalCompareRouterId && !path1.IsIBGP() && !path2.IsIBGP() {
		return nil, nil
	}

	if !SelectionOptions.ExternalCompareRouterId && path1.IsIBGP() != path2.IsIBGP() {
		return nil, fmt.Errorf("this method does not support comparing ebgp with ibgp path")
	}

	// At least one path is not coming from NC, so we get local bgp id.
	id1 := binary.BigEndian.Uint32(path1.GetSource().ID.AsSlice())
	id2 := binary.BigEndian.Uint32(path2.GetSource().ID.AsSlice())

	// If both router ids are same/equal we cannot decide.
	// This case is possible since router ids are arbitrary.
	if id1 == id2 {
		return nil, nil
	} else if id1 < id2 {
		return path1, nil
	} else {
		return path2, nil
	}
}

func compareByNeighborAddress(path1, path2 *Path) *Path {
	// Select the route received from the peer with the lowest peer address as
	// per RFC 4271 9.1.2.2. g

	// Two source-less paths (both locally injected) are a genuine tie.
	// Returning path1 here — the historical behavior — made this a
	// first-argument-wins comparison, which is not a valid ordering:
	// sort.SliceStable permutes such ties arbitrarily, so every D-066
	// metric reload could reshuffle fully-tied local paths and churn
	// exports for no input change (R-037 round-2 review).
	p1 := path1.GetSource().Address
	p2 := path2.GetSource().Address
	if !p1.IsValid() && !p2.IsValid() {
		return nil
	}
	if !p1.IsValid() {
		return path1
	}
	if !p2.IsValid() {
		return path2
	}

	cmp := p1.Compare(p2)
	if cmp < 0 {
		return path1
	} else if cmp > 0 {
		return path2
	}
	return nil
}

func compareByAge(path1, path2 *Path) *Path {
	if !path1.IsIBGP() && !path2.IsIBGP() && !SelectionOptions.ExternalCompareRouterId {
		age1 := path1.GetTimestamp().UnixNano()
		age2 := path2.GetTimestamp().UnixNano()
		if age1 == age2 {
			return nil
		} else if age1 < age2 {
			return path1
		}
		return path2
	}
	return nil
}

// compareByContent (Bendrr R-278) is the penultimate comparator in
// rankBetterPath: a pure determinism tie-break on stable route content for
// pairs on which every operational comparator above abstained (the
// absolute-final step is compareByPathID below, for content-identical
// twins). Before R-278, a complete tie fell through to insertSort's
// positional insert-before-equal, so the winner among fully-tied paths was
// newest-first arrival order: nondeterministic across pods (different
// arrival order, different best path, different exports for identical
// inputs) and churn-prone (every re-add of a tied candidate re-shuffled
// the export — the same churn class the R-037 round-2 fix closed for D-066
// metric reloads, see compareByNeighborAddress). Lower content key
// compares first, matching the lowest-wins convention of the router-ID and
// neighbor-address steps.
//
// SCOPE: fires for ALL complete ties, not only both-source-less (locally
// injected) pairs. Two pair classes reach the bottom: (a) both-source-less
// injected pairs — the R-278 motivation — which tie on age whenever they
// arrive in the same Unix second (and always once external-compare-router-id
// is armed), then tie on router ID (both IsLocal) and neighbor address (both
// invalid, the deliberate R-037 genuine tie); and (b) same-peer ADD-PATH
// twins — different peers never fully tie because compareByNeighborAddress
// splits them, but same-source twins tie on router ID and neighbor address,
// and iBGP twins skip compareByAge entirely. Class (b) is how every OTHER
// pod sees a pod's injected candidate set (mesh-learned twins from one
// neighbor), so scoping the comparator to source-less pairs would fix the
// origin pod and leave every receiving pod arrival-ordered — half a
// determinism claim. Firing everywhere is also the easiest form to prove
// valid (no guard asymmetry to reason about), and the blast radius is
// confined to pairs where every operational comparator already abstained:
// today's order there is arbitrary arrival order, so no preference
// semantics change — only WHICH arbitrary order, now the same on every pod.
// Note this changes the default chain too, independent of the R-277
// selection knobs.
//
// VALIDITY: the canonical content key (computePathContentKey, path.go) is
// a pure function of each path alone and the comparison is a single
// bytes.Compare, so the relation is a strict weak ordering by
// construction — antisymmetric, transitive, and safe for insertSort's
// sort.Search and reSort's sort.SliceStable, unlike the historical
// first-argument-wins fallback R-037 round-2 removed. nil is returned
// ONLY when the two canonical content keys are identical. Byte-identical
// content always yields identical keys; the converse has two documented
// slack cases. First, serialization failures degrade the failing
// component to a normalized header with empty value bytes, so two paths
// whose difference lives entirely inside an unserializable component
// (e.g. two EVPN IP-prefix NLRIs whose Serialize fails on different
// ETags) also tie — deterministically, identically on every pod. Second,
// the key is deliberately canonical rather than wire-faithful: the same
// attribute multiset in a different stored slice order, or with
// different EXTENDED_LENGTH/PARTIAL header encodings, ties here even
// though Path.Equal (hash over stored-order raw TLVs) calls the paths
// unequal — so among key-equal paths the WIRE bytes of the eventually
// exported UPDATE can still depend on which path object won; only the
// ranking is canonicalized.
//
// CONTENT means route content only. Compared, via the memoized key: NLRI
// serialized bytes (ADD-PATH identifiers cannot leak in: this fork keeps
// them in PathNLRI.ID beside the NLRI, and NLRI.Serialize never emits
// them), the MP_REACH nexthop pair — where a plain IPv4 nexthop and its
// IPv4-mapped IPv6 form (::ffff:a.b.c.d) are distinct content, NOT a
// normalized-away encoding artifact: the two forms have distinct wire
// encodings (4 vs 16 nexthop bytes) that survive round-trips, so every
// receiver of the same UPDATE agrees on the form (see appendAddrKey) —
// and every path attribute except
// MP_REACH_NLRI as normalized (type, flags minus EXTENDED_LENGTH and
// PARTIAL, value bytes) entries — the wire header is dropped, so
// header-width and propagation-artifact flag differences are not content
// (round-1 MAJOR-4). Excluded as pod-local or arrival-dependent:
// timestamps, source/peer fields (router ID, neighbor address, AS),
// localID (the locally allocated ADD-PATH identifier — note Calculate
// assigns it AFTER first-add insertSort but implicitWithdraw copies it
// onto a re-add BEFORE insertSort, so a leak would rank re-adds
// differently from first adds), remoteID (handled separately by
// compareByPathID below), and the MP_REACH_NLRI attribute, whose
// in-memory Value embeds localID. Default Serialize omits per-NLRI IDs
// today, but nothing here pins that marshalling default, so MP_REACH is
// excluded outright and its nexthops encoded explicitly — the same stance
// Path.Equal and updateHash take (there so the hash can double as the
// UPDATE batching key). Its remaining content is covered: the AFI/SAFI is
// the destination's own family and the NLRI list is the path's own NLRI,
// both already in the key.
//
// "Identical on every pod that holds the same logical route" holds to
// this extent: wire-learned attrs are normalized at ingestion (every
// received UPDATE passes UpdatePathAttrs4ByteAs, fsm.go, which rewrites
// 2-byte AsPathParam to As4PathParam in place, so a 2-byte AS_PATH
// encoding cannot reach the RIB), header encodings are normalized here,
// and attr slice order is canonicalized. The residual: two API clients
// building the same logical AS_PATH with different param types
// (AsPathParam vs As4PathParam) on different pods would compare unequal —
// still a valid ordering, and unreachable in bendrr, where one driver
// builds every injected path; mixed local/wire pairs never meet here at
// all because compareByLocalOrigin splits them earlier.
//
// ATTRIBUTE ORDER: attribute entries are compared in canonical sorted
// order, not stored slice order. GetPathAttrs preserves arrival order for
// wire-learned attributes but append-then-sorts newly added ones, so the
// same logical path can carry differently-ordered attr slices depending
// on construction history (API-injected on one pod, mesh-learned on
// another). Stored-order comparison would still be a valid ordering, but
// two semantically equal paths could compare unequal — and worse,
// differently-ordered — across pods, defeating the cross-pod determinism
// this comparator exists to provide. Sorting makes the key a function of
// the attribute SET. BGP forbids duplicate attribute types, so the sort
// is a plain relabeling; even for a malformed duplicate-type pair it
// remains deterministic.
//
// COST: the key is memoized on the Path (round-1 MAJOR-2; invalidation
// follows attrsHash exactly — see contentKeyBytes in path.go, including
// the concurrency argument for the first computation), so steady-state
// tied compares are a single allocation-free bytes.Compare and a D-066
// reload reSort stays near the pre-R-278 allocation baseline.
//
// NON-TRANSITIVITY ABOVE: the chain above remains non-transitive through
// compareByMED's comparability groups, and a strict ordering at the
// bottom does not repair that — in principle MED can still complete
// preference 3-cycles that sort.SliceStable resolves arbitrarily (a
// constructive search over 3-group populations found no realized cycle;
// the mechanism is what's documented here).
//
// PLACEMENT: below the location-metric slot in rankBetterPath ONLY, per the
// LOCKSTEP comment above rankPreMetricComparators — a pure determinism
// tie-break must not enter the shared slice nor EqualThroughLocationMetric,
// so R-037 bucket membership for ADD-PATH export is bit-for-bit unchanged.
func compareByContent(path1, path2 *Path) *Path {
	c := comparePathContent(path1, path2)
	if c < 0 {
		return path1
	} else if c > 0 {
		return path2
	}
	return nil
}

// comparePathContent returns a three-way comparison of the memoized
// canonical content keys (see compareByContent for what the key includes
// and excludes, and computePathContentKey in path.go for its layout).
func comparePathContent(path1, path2 *Path) int {
	return bytes.Compare(path1.contentKeyBytes(), path2.contentKeyBytes())
}

// compareByPathID (Bendrr R-278 round-2, review MAJOR-1) is the
// absolute-final comparator: content-identical twins order by ADD-PATH
// path identifier (remoteID), lower first. Without it, byte-identical
// twins — which differ ONLY in path id — still fell to insertSort's
// positional tie, so their order was arrival-dependent and re-add-mobile;
// with bucket-aware export (exportSelector admits ranked bucket members up
// to a slot cap) WHICH twins export was arrival-dependent, and receivers
// see path ids, so the difference is visible on the wire.
//
// Why remoteID is safe here: for wire-learned twins it is the ORIGIN
// pod's exported path identifier — every receiver of the same origin
// holds the same (content, id) pairs, so all receivers agree and re-adds
// are stable. Note what that identifier actually IS: the origin's localID
// from the FindandSetZeroBit allocator — arrival-ordered and reuse-prone,
// an arbitrary origin-assigned value, not content-derived. Receivers
// therefore agree on an ARBITRARY order, and a full withdraw/re-add cycle
// at the origin can reassign the id and reorder every receiver — in
// lockstep. That is still strictly better than the pre-R-278 state, where
// each receiver ordered twins by its own arrival history and pods could
// disagree with no origin-side change at all. For locally injected twins
// remoteID is the driver-chosen path_id, per-path stable, so origin-side
// order is deterministic too. RESIDUAL, stated honestly: cross-pod
// agreement for content-identical LOCAL twins additionally requires the
// driver to assign the same path_ids for the same logical routes on every
// pod — if two pods hold identical content under different ids, they can
// rank the twins differently, though the difference is only visible as a
// path-id swap between routes an operator cannot otherwise tell apart. A
// nil return (complete tie) requires identical content key AND identical
// path id. Same-source paths sharing both are collapsed by
// implicitWithdraw — UNLESS flagged NoImplicitWithdraw (implicitWithdraw
// skips flagged paths), which lets full key-and-id twins coexist; those
// are interchangeable by content and id, so insertSort's positional
// fallback orders them arbitrarily but harmlessly. Otherwise the residual
// positional tie is confined to pairs from distinct sources that every
// comparator above — including neighbor address — failed to split.
func compareByPathID(path1, path2 *Path) *Path {
	if path1.remoteID < path2.remoteID {
		return path1
	} else if path1.remoteID > path2.remoteID {
		return path2
	}
	return nil
}

func (dest *destination) String() string {
	return fmt.Sprintf("Destination NLRI: %s", dest.nlri.String())
}

type DestinationSelectOption struct {
	ID        string
	AS        uint32
	VRF       *Vrf
	adj       bool
	Best      bool
	MultiPath bool
}

func (d *destination) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.GetAllKnownPathList())
}

// Select filters and returns a new destination with selected paths based on the given options.
// When called on an active (non-snapshot) destination, caller must hold the appropriate shard lock.
// When called on a snapshot destination, no lock is required as the data is already a stable copy.
// Returns a newly created destination, never modifies the receiver.
func (d *destination) Select(option ...DestinationSelectOption) *destination {
	id := GLOBAL_RIB_NAME
	var vrf *Vrf
	adj := false
	best := false
	mp := false
	as := uint32(0)
	for _, o := range option {
		if o.ID != "" {
			id = o.ID
		}
		if o.VRF != nil {
			vrf = o.VRF
		}
		adj = o.adj
		best = o.Best
		mp = o.MultiPath
		as = o.AS
	}
	var paths []*Path
	if adj {
		// adj mode: caller must hold lock if this is an active destination
		paths = make([]*Path, len(d.knownPathList))
		copy(paths, d.knownPathList)
	} else {
		paths = d.GetKnownPathList(id, as)
		if vrf != nil {
			ps := make([]*Path, 0, len(paths))
			for _, p := range paths {
				if CanImportToVrf(vrf, p) {
					ps = append(ps, p.ToLocal())
				}
			}
			paths = ps
		}
		if len(paths) == 0 {
			return nil
		}
		if best {
			if !mp {
				paths = []*Path{paths[0]}
			} else {
				ps := make([]*Path, 0, len(paths))
				var best *Path
				for _, p := range paths {
					if best == nil {
						best = p
						ps = append(ps, p)
					} else if best.Compare(p) == 0 {
						ps = append(ps, p)
					}
				}
				paths = ps
			}
		}
	}
	return newDestination(d.nlri, 0, paths...)
}
