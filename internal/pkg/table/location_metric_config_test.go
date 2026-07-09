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

package table

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const validMetricYAML = `
version: 1
global_admin: 64500
perspective_location_id: 104
destinations:
  102: 50
  106: 25
  185: 120
  201: 60
`

// Mirrors config/community-name-registry.example.yaml in the bendrr repo
// (extra top-level keys must be ignored by the loader).
const validRegistryYAML = `
version: 1
global_admin: 64500
sub_partitions:
  2001: peering
scope:
  1201: regional
region:
  1: amer
location:
  102: lax
  104: ord
  106: dfw
  185: fra
  201: den
`

func writeTempYAML(t *testing.T, name, contents string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(p, []byte(contents), 0o644))
	return p
}

func TestLoadLocationMetricFile_valid(t *testing.T) {
	defer resetLocationMetric()

	mapPath := writeTempYAML(t, "metric.yaml", validMetricYAML)
	require.NoError(t, LoadLocationMetricFile(mapPath, ""))

	tbl := CurrentLocationMetric()
	assert.True(t, tbl.Enabled())
	assert.Equal(t, uint32(64500), tbl.GlobalAdmin)
	assert.Equal(t, uint32(104), tbl.PerspectiveLocationID)
	assert.Equal(t, uint32(50), tbl.Destinations[102])
	assert.Equal(t, uint32(120), tbl.Destinations[185])

	// The startup load records the mounted paths for the D-066 reload.
	recordedMap, recordedReg := LocationMetricPaths()
	assert.Equal(t, mapPath, recordedMap)
	assert.Equal(t, "", recordedReg)
}

func TestLoadLocationMetricFile_withRegistry(t *testing.T) {
	defer resetLocationMetric()

	mapPath := writeTempYAML(t, "metric.yaml", validMetricYAML)
	regPath := writeTempYAML(t, "registry.yaml", validRegistryYAML)
	require.NoError(t, LoadLocationMetricFile(mapPath, regPath))
	assert.True(t, CurrentLocationMetric().Enabled())
}

func TestLoadLocationMetricFile_ownRowStrippedNotStored(t *testing.T) {
	defer resetLocationMetric()

	// Config generation may emit the perspective's own row; it must be dropped
	// so the computed own-location 0 default cannot be overridden.
	mapPath := writeTempYAML(t, "metric.yaml", `
global_admin: 64500
perspective_location_id: 104
destinations:
  104: 7
  102: 50
  106: 25
  185: 120
  201: 60
`)
	require.NoError(t, LoadLocationMetricFile(mapPath, ""))

	_, hasOwnRow := CurrentLocationMetric().Destinations[104]
	assert.False(t, hasOwnRow)
}

func TestLoadLocationMetricFile_missingFields(t *testing.T) {
	defer resetLocationMetric()

	cases := map[string]string{
		"no global_admin": `
perspective_location_id: 104
destinations: {102: 50}
`,
		"no perspective": `
global_admin: 64500
destinations: {102: 50}
`,
		"empty destinations": `
global_admin: 64500
perspective_location_id: 104
`,
	}
	for name, yamlBody := range cases {
		t.Run(name, func(t *testing.T) {
			mapPath := writeTempYAML(t, "metric.yaml", yamlBody)
			assert.Error(t, LoadLocationMetricFile(mapPath, ""))
		})
	}
}

func TestLoadLocationMetricFile_sentinelCollision(t *testing.T) {
	defer resetLocationMetric()

	mapPath := writeTempYAML(t, "metric.yaml", `
global_admin: 64500
perspective_location_id: 104
destinations:
  102: 4294967294
`)
	err := LoadLocationMetricFile(mapPath, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sentinel")
}

func TestLoadLocationMetricFile_registryMissingLocation(t *testing.T) {
	defer resetLocationMetric()

	// Map omits fra (185), which the registry declares — must fail startup.
	mapPath := writeTempYAML(t, "metric.yaml", `
global_admin: 64500
perspective_location_id: 104
destinations:
  102: 50
  106: 25
  201: 60
`)
	regPath := writeTempYAML(t, "registry.yaml", validRegistryYAML)
	err := LoadLocationMetricFile(mapPath, regPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "185")
}

func TestLoadLocationMetricFile_registryUnknownDestination(t *testing.T) {
	defer resetLocationMetric()

	// Map references location 999, unknown to the registry — likely a typo.
	mapPath := writeTempYAML(t, "metric.yaml", `
global_admin: 64500
perspective_location_id: 104
destinations:
  102: 50
  106: 25
  185: 120
  201: 60
  999: 10
`)
	regPath := writeTempYAML(t, "registry.yaml", validRegistryYAML)
	err := LoadLocationMetricFile(mapPath, regPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "999")
}

func TestLoadLocationMetricFile_registryAdminMismatch(t *testing.T) {
	defer resetLocationMetric()

	mapPath := writeTempYAML(t, "metric.yaml", validMetricYAML)
	regPath := writeTempYAML(t, "registry.yaml", `
global_admin: 14593
location:
  102: lax
  104: ord
  106: dfw
  185: fra
  201: den
`)
	err := LoadLocationMetricFile(mapPath, regPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "global_admin mismatch")
}

func TestLoadLocationMetricFile_perspectiveNotInRegistry(t *testing.T) {
	defer resetLocationMetric()

	mapPath := writeTempYAML(t, "metric.yaml", `
global_admin: 64500
perspective_location_id: 300
destinations:
  102: 50
  104: 40
  106: 25
  185: 120
  201: 60
`)
	regPath := writeTempYAML(t, "registry.yaml", validRegistryYAML)
	err := LoadLocationMetricFile(mapPath, regPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "perspective_location_id 300")
}
