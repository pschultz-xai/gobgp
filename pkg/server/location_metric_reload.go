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

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// LocationMetricReloadStats reports what a D-066 location-metric reload did.
type LocationMetricReloadStats struct {
	MapPath               string
	RegistryPath          string
	PerspectiveLocationID uint32
	MetricRows            int
	DryRun                bool
	// MapChanged is false when the re-read file ranks identically to the
	// running table; the RIB walk is skipped in that case.
	MapChanged bool
	// RibDestinations is the number of destinations examined.
	RibDestinations int
	// RerankedDestinations is the number whose best-path order or R-037
	// bucket partition changed (either requires re-export).
	RerankedDestinations int
	// AnnouncedPaths / WithdrawnPaths are UPDATE messages queued to peers
	// as a result of the re-rank (across all peers).
	AnnouncedPaths int
	WithdrawnPaths int
	Duration       time.Duration
}

// ReloadLocationMetric implements the D-066 explicit-trigger reload for the
// D-014 location-metric map: re-read and registry-validate the mounted map,
// swap it atomically, and run a full best-path recomputation with minimal
// re-export (same operation class as a policy soft-reset). On validation
// failure the running map is kept and the error returned (fail-safe).
//
// mapPath and registryPath default to the paths recorded at startup; either
// can be overridden per call. dryRun validates and reports without applying
// (side-effect-free).
//
// The recompute runs as one management operation: it holds the server lock
// exclusively for the duration (like a policy soft-reset walk), so live
// AddPath/DeletePath calls queue behind it. Metric-map rollouts are staged
// per location (D-066), so that pause is a planned, per-instance event.
func (s *BgpServer) ReloadLocationMetric(mapPath, registryPath string, dryRun bool) (*LocationMetricReloadStats, error) {
	startupMap, startupReg := table.LocationMetricPaths()
	if mapPath == "" {
		mapPath = startupMap
	}
	if registryPath == "" {
		registryPath = startupReg
	}
	if mapPath == "" {
		return nil, fmt.Errorf("location-metric reload: no map mounted at startup (--location-metric-file) and no map path supplied")
	}

	newTbl, err := table.ParseLocationMetricFile(mapPath, registryPath)
	if err != nil {
		s.logger.Warn("Location-metric reload rejected; keeping running map",
			slog.String("Topic", "Config"),
			slog.String("File", mapPath),
			slog.String("Error", err.Error()))
		return nil, err
	}

	stats := &LocationMetricReloadStats{
		MapPath:               mapPath,
		RegistryPath:          registryPath,
		PerspectiveLocationID: newTbl.PerspectiveLocationID,
		MetricRows:            len(newTbl.Destinations),
		DryRun:                dryRun,
		MapChanged:            !newTbl.Equal(table.CurrentLocationMetric()),
	}
	if dryRun {
		return stats, nil
	}

	err = s.mgmtOperation(func() error {
		start := time.Now()
		// Re-check under the server lock; an earlier reload may have raced.
		stats.MapChanged = !newTbl.Equal(table.CurrentLocationMetric())
		if !stats.MapChanged {
			s.logger.Info("Location-metric reload: map unchanged, skipping recompute",
				slog.String("Topic", "Config"),
				slog.String("File", mapPath))
			return nil
		}

		oldTbl := table.CurrentLocationMetric()
		table.InstallLocationMetric(newTbl)

		// The management operation holds the server lock exclusively, so no
		// concurrent propagateUpdate can mutate tables or per-peer export
		// bookkeeping during the walk; per-prefix propagation bucket locks
		// are subsumed by that exclusivity. Off-loop readers (ListPath,
		// soft-reconfig) stay safe via shard locks and the peer.advMu leaf.
		// oldTbl lets the walk catch destinations whose bucket membership
		// changed without the ranked order moving (R-037).
		total, changed := s.globalRib.ReRankDestinations(oldTbl, func(dsts []*table.Update) {
			s.propagateReRankedDestinations(dsts, stats)
		})
		stats.RibDestinations = total
		stats.RerankedDestinations = changed

		// Route-server RIBs must keep the sorted invariant too, but Bendrr
		// runs no route-server clients and their per-client views are not
		// re-exported here.
		if _, rsChanged := s.rsRib.ReRankDestinations(oldTbl, nil); rsChanged > 0 {
			s.logger.Warn("Location-metric reload re-ranked route-server RIB destinations; route-server client views are not re-exported",
				slog.String("Topic", "Config"),
				slog.Int("Destinations", rsChanged))
		}

		stats.Duration = time.Since(start)
		s.logger.Info("Location-metric map reloaded",
			slog.String("Topic", "Config"),
			slog.String("File", mapPath),
			slog.Uint64("PerspectiveLocationID", uint64(newTbl.PerspectiveLocationID)),
			slog.Int("MetricRows", stats.MetricRows),
			slog.Int("RibDestinations", stats.RibDestinations),
			slog.Int("RerankedDestinations", stats.RerankedDestinations),
			slog.Int("AnnouncedPaths", stats.AnnouncedPaths),
			slog.Int("WithdrawnPaths", stats.WithdrawnPaths),
			slog.Duration("Duration", stats.Duration))
		return nil
	}, true)
	if err != nil {
		return nil, err
	}
	return stats, nil
}

// propagateReRankedDestinations exports the consequences of a metric-map
// re-rank for one batch of changed destinations. It mirrors
// propagateUpdateToNeighbors' two export modes, minimized for the reload
// case where no path content changed — only rank order:
//
//   - ADD-PATH send peers: re-sync the advertised set to the new top-SendMax
//     ranked order (announce newly promoted paths, withdraw displaced ones);
//     paths that stay inside the cut are not re-sent.
//   - plain peers: announce the new best / withdraw via the standard
//     GetChanges old-vs-new diff; unchanged best costs nothing.
//
// Caller is the ReRankDestinations walk inside the reload mgmt operation
// (exclusive server lock); see the locking note there.
func (s *BgpServer) propagateReRankedDestinations(dsts []*table.Update, stats *LocationMetricReloadStats) {
	if table.SelectionOptions.DisableBestPathSelection {
		return
	}

	gBestList, gOldList, mpathList, multipathUpdate, multipathWithdraw := dstsToPaths(table.GLOBAL_RIB_NAME, 0, dsts)
	s.notifyBestWatcher(gBestList, mpathList, multipathUpdate, multipathWithdraw)

	for _, targetPeer := range s.neighborMap {
		if targetPeer.isRouteServerClient() {
			continue
		}

		func() {
			targetPeer.routeRefreshInProgress.RLock()
			defer targetPeer.routeRefreshInProgress.RUnlock()
			if !needToAdvertise(targetPeer) {
				return
			}

			conf := targetPeer.fsm.pConf.ReadOnly()
			peerVrf := conf.Config.Vrf

			paths := make([]*table.Path, 0, len(dsts))
			var plainBest, plainOld []*table.Path
			for i, u := range dsts {
				// reSort reports a change only when order or bucket
				// partition moved, either of which needs at least two
				// paths, so KnownPathList is non-empty.
				f := u.KnownPathList[0].GetFamily()
				if peerVrf != "" {
					switch f {
					case bgp.RF_IPv4_VPN:
						f = bgp.RF_IPv4_UC
					case bgp.RF_IPv6_VPN:
						f = bgp.RF_IPv6_UC
					case bgp.RF_FS_IPv4_VPN:
						f = bgp.RF_FS_IPv4_UC
					case bgp.RF_FS_IPv6_VPN:
						f = bgp.RF_FS_IPv6_UC
					}
				}
				if targetPeer.isAddPathSendEnabled(f) {
					paths = append(paths, s.syncRankedAddPathSetFromList(targetPeer, f, u.KnownPathList, nil)...)
				} else {
					plainBest = append(plainBest, gBestList[i])
					plainOld = append(plainOld, gOldList[i])
				}
			}
			paths = append(paths, s.processOutgoingPaths(targetPeer, plainBest, plainOld)...)

			if len(paths) == 0 {
				return
			}
			targetPeer.updateRoutes(paths...)
			targetPeer.markExportDumpDirty(paths)
			sendfsmOutgoingMsg(targetPeer, paths)
			for _, p := range paths {
				if p.IsWithdraw {
					stats.WithdrawnPaths++
				} else {
					stats.AnnouncedPaths++
				}
			}
		}()
	}
}
