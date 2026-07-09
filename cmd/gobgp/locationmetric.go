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

package main

import (
	"fmt"

	"github.com/osrg/gobgp/v4/api"
	"github.com/spf13/cobra"
)

// Bendrr fork (D-066): CLI for the explicit location-metric map reload.
func newLocationMetricCmd() *cobra.Command {
	var mapPath, registryPath string
	var dryRun bool

	reloadCmd := &cobra.Command{
		Use:   "reload",
		Short: "re-read, validate and apply the mounted location-metric map (D-066)",
		Run: func(cmd *cobra.Command, args []string) {
			resp, err := client.ReloadLocationMetric(ctx, &api.ReloadLocationMetricRequest{
				MapPath:      mapPath,
				RegistryPath: registryPath,
				DryRun:       dryRun,
			})
			if err != nil {
				exitWithError(err)
			}
			if dryRun {
				fmt.Printf("dry-run: map valid (perspective %d, %d rows); would %s\n",
					resp.PerspectiveLocationId, resp.MetricRows,
					map[bool]string{true: "apply changes", false: "be a no-op (map unchanged)"}[resp.MapChanged])
				return
			}
			if !resp.MapChanged {
				fmt.Printf("map unchanged (perspective %d, %d rows); recompute skipped\n",
					resp.PerspectiveLocationId, resp.MetricRows)
				return
			}
			fmt.Printf("reloaded: perspective %d, %d rows; %d/%d destinations re-ranked; %d announced, %d withdrawn; %d ms\n",
				resp.PerspectiveLocationId, resp.MetricRows,
				resp.RerankedDestinations, resp.RibDestinations,
				resp.AnnouncedPaths, resp.WithdrawnPaths, resp.DurationMs)
		},
	}
	reloadCmd.PersistentFlags().StringVar(&mapPath, "map-file", "", "override the map path recorded at startup")
	reloadCmd.PersistentFlags().StringVar(&registryPath, "registry-file", "", "override the registry path recorded at startup")
	reloadCmd.PersistentFlags().BoolVar(&dryRun, "dry-run", false, "validate and report without applying")

	locationMetricCmd := &cobra.Command{
		Use:   "locationmetric",
		Short: "Bendrr location-metric map operations",
	}
	locationMetricCmd.AddCommand(reloadCmd)
	return locationMetricCmd
}
