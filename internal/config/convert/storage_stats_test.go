// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert

import (
	"encoding/json"
	"math/bits"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/obi"
)

// Every storage flag of metrics.features has a config v2 family of the same
// name: the single-metric flags as leaves, which are exported, the others as
// umbrellas, which are only accepted. A new storage flag fails here until it
// has one.
func TestStorageStatsFamiliesCoverTheFeatureMapper(t *testing.T) {
	known := map[string]export.Features{}
	for _, f := range storageStatsFamilies {
		assert.Equal(t, 1, bits.OnesCount(uint(f.feature)), "%s is a leaf: one flag", f.name)
		known[f.name] = f.feature
	}
	for _, f := range storageStatsUmbrellas {
		assert.Greater(t, bits.OnesCount(uint(f.feature)), 1, "%s is an umbrella", f.name)
		known[f.name] = f.feature
	}
	for name, feature := range export.FeatureMapper {
		if !strings.HasPrefix(name, "storage_") {
			continue
		}
		assert.Equal(t, feature, known[name], "config v2 family of metrics.features flag %s", name)
		delete(known, name)
	}
	assert.Empty(t, known, "families that are no metrics.features flag")
}

// The config v2 schema lists every family the importer accepts.
func TestStorageStatsFamiliesInTheV2Schema(t *testing.T) {
	data, err := os.ReadFile("../../../devdocs/config/version-2.0/obi-extension.schema.json")
	require.NoError(t, err)
	var doc any
	require.NoError(t, json.Unmarshal(data, &doc))
	enum := jsonPath(t, doc, "$defs", "Network", "properties", "stats", "properties", "features", "items", "enum")
	var got []string
	for _, v := range enum.([]any) {
		got = append(got, v.(string))
	}
	for _, families := range [][]storageStatsFamily{storageStatsFamilies, storageStatsUmbrellas} {
		for _, f := range families {
			assert.Contains(t, got, f.name)
		}
	}
}

func jsonPath(t *testing.T, doc any, path ...string) any {
	t.Helper()
	for _, p := range path {
		m, ok := doc.(map[string]any)
		require.True(t, ok, "no object at %q", p)
		doc, ok = m[p]
		require.True(t, ok, "no key %q", p)
	}
	return doc
}

// Each storage flag goes out as its family and comes back as the same flag.
func TestStorageStatsFamiliesRoundTrip(t *testing.T) {
	t.Parallel()
	for _, f := range storageStatsFamilies {
		t.Run(f.name, func(t *testing.T) {
			t.Parallel()
			cfg := defaultRuntimeConfig()
			cfg.Prometheus.Port = 9090
			cfg.Metrics.Features = export.FeatureStatsTCPRtt | f.feature

			_, ext := RuntimeToV2(&cfg)
			require.Equal(t, true, value(t, ext.Capture.Network, "stats", "enabled"))
			require.ElementsMatch(t, []string{"tcp_rtt", f.name}, value(t, ext.Capture.Network, "stats", "features"))

			got, err := V2ToRuntime(ext)
			require.NoError(t, err)
			assert.Equal(t, cfg.Metrics.Features, got.Metrics.Features)
		})
	}
}

// Storage alone enables the stats section, and an umbrella flag is exported
// as its leaves.
func TestRuntimeToV2StorageUmbrellaExportsLeaves(t *testing.T) {
	t.Parallel()
	cfg := defaultRuntimeConfig()
	cfg.OTELMetrics.MetricsEndpoint = "http://localhost:4318"
	cfg.Metrics.Features = export.FeatureStorageBlock | export.FeatureStorageFSIo

	_, ext := RuntimeToV2(&cfg)

	require.Equal(t, true, value(t, ext.Capture.Network, "stats", "enabled"))
	require.ElementsMatch(t, []string{
		"storage_block_duration", "storage_block_io", "storage_block_queue", "storage_block_errors",
		"storage_block_flush", "storage_block_discard", "storage_block_pending", "storage_fs_io",
	}, value(t, ext.Capture.Network, "stats", "features"))

	got, err := V2ToRuntime(ext)
	require.NoError(t, err)
	assert.Equal(t, cfg.Metrics.Features, got.Metrics.Features)
}

func TestV2ToRuntimeStorageUmbrellas(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		features []string
		want     export.Features
	}{
		"block":                     {[]string{"storage_block"}, export.FeatureStorageBlock},
		"fs":                        {[]string{"storage_fs"}, export.FeatureStorageFS},
		"nfs":                       {[]string{"storage_nfs"}, export.FeatureStorageNFS},
		"block umbrella and a leaf": {[]string{"storage_block", "storage_block_io"}, export.FeatureStorageBlock},
		// queue.depth is in no umbrella, as in metrics.features.
		"queue depth is not in storage_block": {
			[]string{"storage_block", "storage_block_queue_depth"},
			export.FeatureStorageBlock | export.FeatureStorageBlockQueueDepth,
		},
		// Stacked volumes are opt-in, as in metrics.features.
		"volumes are not in storage_block": {
			[]string{"storage_block", "storage_block_volumes"},
			export.FeatureStorageBlock | export.FeatureStorageBlockVolumes,
		},
		// So is the pod attribution of block I/O.
		"pod is not in storage_block": {
			[]string{"storage_block", "storage_block_pod"},
			export.FeatureStorageBlock | export.FeatureStorageBlockPod,
		},
		"unknown names are ignored": {[]string{"storage_nothing", "tcp_rtt"}, export.FeatureStatsTCPRtt},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, ext := RuntimeToV2(nil)
			ext.Capture.Network.Stats.Enabled = true
			ext.Capture.Network.Stats.Features = tc.features
			got, err := V2ToRuntime(ext)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got.Metrics.Features&v2StatsMetricsFeatureMask)
		})
	}
}

// A v2 stats section decides every stats and storage flag: a flag of the base
// config that its list leaves out is cleared, and enabled: true alone still
// means the TCP families only.
func TestV2StatsSectionReplacesTheBaseStorageFlags(t *testing.T) {
	t.Parallel()
	base := func() *obi.Config {
		cfg := runtimeConfigDefaults()
		cfg.Metrics.Features = export.FeatureApplicationRED | export.FeatureStorageBlock |
			export.FeatureStorageBlockQueueDepth | export.FeatureStorageBlockVolumes | export.FeatureStorageBlockPod |
			export.FeatureStorageFS | export.FeatureStorageNFS
		return &cfg
	}

	t.Run("a list", func(t *testing.T) {
		t.Parallel()
		cfg := base()
		src := &schema.Extension{}
		src.Capture.Network.Stats.Features = []string{"tcp_rtt", "storage_fs_io"}
		applyV2MetricsEnablement(cfg, src, false)
		assert.Equal(t, export.FeatureApplicationRED|export.FeatureStatsTCPRtt|export.FeatureStorageFSIo,
			cfg.Metrics.Features)
	})
	t.Run("enabled alone", func(t *testing.T) {
		t.Parallel()
		cfg := base()
		src := &schema.Extension{}
		src.Capture.Network.Stats.Enabled = true
		applyV2MetricsEnablement(cfg, src, false)
		assert.Equal(t, export.FeatureApplicationRED|export.FeatureStats, cfg.Metrics.Features)
	})
	t.Run("no stats section", func(t *testing.T) {
		t.Parallel()
		cfg := base()
		want := cfg.Metrics.Features
		applyV2MetricsEnablement(cfg, &schema.Extension{}, false)
		assert.Equal(t, want, cfg.Metrics.Features, "the base flags stay")
	})
}
