// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package export

import (
	"testing"

	"github.com/caarlos0/env/v11"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestFeatureYAML(t *testing.T) {
	doc := struct {
		Features Features
	}{}
	require.NoError(t,
		yaml.Unmarshal([]byte(`features: [application, application_span_otel, application_runtime]`), &doc))

	assert.True(t, doc.Features.has(FeatureApplicationRED))
	assert.True(t, doc.Features.has(FeatureSpanOTel))
	assert.True(t, doc.Features.has(FeatureApplicationRuntime))
	assert.True(t, doc.Features.has(FeatureApplicationRED|FeatureSpanOTel))
	assert.False(t, doc.Features.has(FeatureSpanLegacy))
	assert.False(t, doc.Features.has(FeatureApplicationRED|FeatureSpanLegacy))
	assert.False(t, doc.Features.has(FeatureAll))
}

func TestFeatureEnv(t *testing.T) {
	doc := struct {
		Features Features `env:"FOO"`
	}{}
	t.Setenv("FOO", "network")
	require.NoError(t, env.Parse(&doc))

	assert.True(t, doc.Features.has(FeatureNetwork))
	assert.False(t, doc.Features.has(FeatureSpanOTel))
	assert.False(t, doc.Features.has(FeatureSpanLegacy))
	assert.False(t, doc.Features.has(FeatureAll))
}

func TestFeatureEnv_NetworkFlowPackets(t *testing.T) {
	doc := struct {
		Features Features `env:"FOO"`
	}{}
	t.Setenv("FOO", "network_flow_packets")
	require.NoError(t, env.Parse(&doc))

	assert.True(t, doc.Features.has(FeatureNetworkFlowPackets))
	assert.True(t, doc.Features.NetworkFlowPackets())
	assert.True(t, doc.Features.AnyNetwork())
	assert.False(t, doc.Features.NetworkBytes())
	assert.False(t, doc.Features.has(FeatureAll))
}

func TestFeatureEnv_Separator(t *testing.T) {
	doc := struct {
		Features Features `env:"FOO" envSeparator:","`
	}{}
	t.Setenv("FOO", "network,application,application_span_otel,application_runtime")
	require.NoError(t, env.Parse(&doc))

	assert.True(t, doc.Features.has(FeatureNetwork))
	assert.True(t, doc.Features.has(FeatureApplicationRED|FeatureSpanOTel))
	assert.True(t, doc.Features.AppRuntime())
	assert.False(t, doc.Features.has(FeatureSpanLegacy))
	assert.False(t, doc.Features.has(FeatureAll))
}

// The three names form a bundle: "application" enables both halves, and the individual
// names select them, mirroring how "stats" bundles the stats_* features.
func TestFeatureApplicationSizes(t *testing.T) {
	for _, tt := range []struct {
		name     string
		features []string
		red      bool
		sizes    bool
	}{
		{name: "application bundles both", features: []string{"application"}, red: true, sizes: true},
		{name: "application_red alone", features: []string{"application_red"}, red: true},
		{name: "application_sizes alone", features: []string{"application_sizes"}, sizes: true},
		{name: "both halves listed", features: []string{"application_red", "application_sizes"}, red: true, sizes: true},
		{name: "bundle plus a half is idempotent", features: []string{"application", "application_sizes"}, red: true, sizes: true},
		{name: "bundle plus the other half", features: []string{"application", "application_red"}, red: true, sizes: true},
		{name: "all", features: []string{"all"}, red: true, sizes: true},
		{name: "wildcard", features: []string{"*"}, red: true, sizes: true},
		{name: "unrelated feature only", features: []string{"network"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			features := mustLoadFeatures(t, tt.features...)
			assert.Equal(t, tt.red, features.AppRED())
			assert.Equal(t, tt.sizes, features.AppSizes())
		})
	}
}

// The size bit has to reach the masks that decide whether application telemetry is on at
// all, otherwise a sizes-only list would look like "no application metrics requested".
func TestFeatureApplicationSizesCountsAsAppO11y(t *testing.T) {
	sizesOnly := mustLoadFeatures(t, "application_sizes")

	assert.True(t, sizesOnly.AnyAppO11yMetric())
	assert.True(t, sizesOnly.AppOrSpan())
	assert.True(t, AppO11yFeatures.has(FeatureApplicationSizes))
}

// "application" has to keep meaning what it meant before the split, so that existing
// feature lists are unaffected.
func TestFeatureApplicationIsBackwardsCompatible(t *testing.T) {
	assert.Equal(t,
		FeatureApplicationRED|FeatureApplicationSizes,
		mustLoadFeatures(t, "application"))
}

func TestFeatureApplicationAliasDoesNotIncludeRuntime(t *testing.T) {
	features := mustLoadFeatures(t, "application")

	assert.True(t, features.has(FeatureApplicationRED))
	assert.False(t, features.has(FeatureApplicationRuntime))
	assert.False(t, AppO11yFeatures.has(FeatureApplicationRuntime))
	assert.True(t, mustLoadFeatures(t, "application_runtime").AnyAppO11yMetric())
	assert.True(t, mustLoadFeatures(t, "application_runtime").AppOrSpan())
}

func mustLoadFeatures(t *testing.T, names ...string) Features {
	t.Helper()
	features, err := LoadFeatures(names)
	require.NoError(t, err)
	return features
}

func TestLoadFeaturesRejectsUnknownNames(t *testing.T) {
	_, err := LoadFeatures([]string{"application_jvm"})
	require.ErrorContains(t, err, `unknown metrics feature "application_jvm"`)

	_, err = LoadFeatures([]string{"application", "application_runtme"})
	require.ErrorContains(t, err, "application_runtme")

	// empty entries (trailing commas in env values) are not an error
	features, err := LoadFeatures([]string{"application", ""})
	require.NoError(t, err)
	assert.True(t, features.has(FeatureApplicationRED))

	// the error names the valid features so a typo is self-diagnosing
	_, err = LoadFeatures([]string{"no_such_feature"})
	require.ErrorContains(t, err, "application_runtime")
}

// An unset OTEL_EBPF_METRICS_FEATURES resolves to an empty envDefault string
// (perapp.GlobalMetricsConfig), so UnmarshalText("") runs on every default
// deployment and must keep yielding Undefined rather than an error.
func TestFeatureUnmarshalTextEmpty(t *testing.T) {
	var features Features
	require.NoError(t, features.UnmarshalText(nil))
	assert.True(t, features.Undefined())

	require.NoError(t, features.UnmarshalText([]byte("")))
	assert.True(t, features.Undefined())
}

func TestFeatureEnv_All(t *testing.T) {
	doc := struct {
		Features Features `env:"FOO" envSeparator:","`
	}{}
	t.Setenv("FOO", "all")
	require.NoError(t, env.Parse(&doc))

	assert.True(t, doc.Features.has(FeatureNetwork))
	assert.True(t, doc.Features.has(FeatureApplicationRED|FeatureSpanOTel))
	assert.True(t, doc.Features.has(FeatureSpanLegacy))
	assert.True(t, doc.Features.has(FeatureAll))
}

func TestFeatureYAML_All(t *testing.T) {
	doc := struct {
		Features Features
	}{}
	require.NoError(t,
		yaml.Unmarshal([]byte(`features: ["*"]`), &doc))

	assert.True(t, doc.Features.has(FeatureApplicationRED))
	assert.True(t, doc.Features.has(FeatureSpanOTel))
	assert.True(t, doc.Features.has(FeatureSpanLegacy))
	assert.True(t, doc.Features.has(FeatureAll))
}

func TestFeatureYAML_Error(t *testing.T) {
	doc := struct {
		Features Features
	}{}
	require.Error(t,
		yaml.Unmarshal([]byte(`features: {hello: world}`), &doc))
	require.Error(t,
		yaml.Unmarshal([]byte(`features: [{hello: world}]`), &doc))
}

func TestFeatureEmpty(t *testing.T) {
	t.Run("empty YAML", func(t *testing.T) {
		doc := struct {
			Features Features
		}{}
		require.NoError(t,
			yaml.Unmarshal([]byte(`features: []`), &doc))
		require.True(t, doc.Features.Empty())
		require.False(t, doc.Features.Undefined())
	})
}

func TestResolveSpanMetricsConflict(t *testing.T) {
	t.Run("only legacy no conflict", func(t *testing.T) {
		f := FeatureSpanLegacy | FeatureNetwork
		resolved := f.ResolveSpanMetricsConflict()
		assert.False(t, resolved)
		assert.True(t, f.has(FeatureSpanLegacy))
	})
	t.Run("only otel no conflict", func(t *testing.T) {
		f := FeatureSpanOTel
		resolved := f.ResolveSpanMetricsConflict()
		assert.False(t, resolved)
		assert.True(t, f.has(FeatureSpanOTel))
	})
	t.Run("both enabled removes legacy keeps otel", func(t *testing.T) {
		f := FeatureSpanLegacy | FeatureSpanOTel | FeatureNetwork
		resolved := f.ResolveSpanMetricsConflict()
		assert.True(t, resolved)
		assert.True(t, f.has(FeatureSpanOTel))
		assert.True(t, f.has(FeatureNetwork))
		assert.False(t, f.has(FeatureSpanLegacy))
	})
	t.Run("neither enabled", func(t *testing.T) {
		f := FeatureNetwork
		resolved := f.ResolveSpanMetricsConflict()
		assert.False(t, resolved)
		assert.True(t, f.has(FeatureNetwork))
	})
}

func TestInvalidSpanMetricsConfig(t *testing.T) {
	tests := []struct {
		name     string
		features Features
		expected bool
	}{
		{"only legacy", FeatureSpanLegacy, false},
		{"only otel", FeatureSpanOTel, false},
		{"both legacy and otel", FeatureSpanLegacy | FeatureSpanOTel, true},
		{"both via FeatureAll", FeatureAll, false},
		{"both plus other features", FeatureSpanLegacy | FeatureSpanOTel | FeatureNetwork, true},
		{"neither", FeatureNetwork, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.features.InvalidSpanMetricsConfig())
		})
	}
}

func TestFeatureJSONSchemaFlagsDeprecatedNames(t *testing.T) {
	items := Features(0).JSONSchema().Items
	require.Len(t, items.OneOf, 2)

	assert.False(t, items.OneOf[0].Deprecated)
	assert.Contains(t, items.OneOf[0].Enum, "application_span_otel")
	assert.Contains(t, items.OneOf[0].Enum, "*")
	assert.NotContains(t, items.OneOf[0].Enum, "application_span")
	assert.NotContains(t, items.OneOf[0].Enum, "application_span_sizes")
	assert.NotContains(t, items.OneOf[0].Enum, "storage_block_queue_depth")

	assert.True(t, items.OneOf[1].Deprecated)
	assert.Equal(t, []any{"application_span", "application_span_sizes", "storage_block_queue_depth"}, items.OneOf[1].Enum)

	// the schema names the migration target instead of pointing elsewhere for it
	assert.Contains(t, items.OneOf[1].Description, "application_span (use application_span_otel)")
	assert.Contains(t, items.OneOf[1].Description, "application_span_sizes (no direct replacement)")
	assert.Contains(t, items.OneOf[1].Description, "storage_block_queue_depth (no direct replacement)")
}

func TestDeprecatedEnabled(t *testing.T) {
	assert.Equal(t,
		[]DeprecatedFeature{{Name: "application_span", Replacement: "application_span_otel"}},
		mustLoadFeatures(t, "application", "application_span").DeprecatedEnabled())

	assert.Equal(t,
		[]DeprecatedFeature{{Name: "application_span_sizes"}},
		mustLoadFeatures(t, "application_span_sizes").DeprecatedEnabled())

	assert.Empty(t, mustLoadFeatures(t, "application", "application_span_otel").DeprecatedEnabled())
}

func TestStorageBlockFeatureParsing(t *testing.T) {
	var f Features
	require.NoError(t, yaml.Unmarshal([]byte(`["storage_block"]`), &f))
	assert.True(t, f.StorageBlock())
	assert.True(t, f.StorageBlockDuration())
	assert.True(t, f.StorageBlockIo())
	assert.True(t, f.StorageBlockQueue())
	assert.True(t, f.StorageBlockErrors())
	assert.True(t, f.StatMetrics()) // storage rides the stats pipeline

	var q Features
	require.NoError(t, yaml.Unmarshal([]byte(`["storage_block_queue"]`), &q))
	assert.True(t, q.StorageBlock())
	assert.True(t, q.StorageBlockQueue())
	assert.False(t, q.StorageBlockErrors())

	var e Features
	require.NoError(t, yaml.Unmarshal([]byte(`["storage_block_errors"]`), &e))
	assert.True(t, e.StorageBlock())
	assert.True(t, e.StorageBlockErrors())
	assert.False(t, e.StorageBlockQueue())
}

// Flushes and discards have metrics of their own, in the storage_block umbrella
// and the wildcard. Asked for alone, they need the block probes but none of the
// read and write metrics.
func TestStorageBlockFlushDiscardFeatureParsing(t *testing.T) {
	umbrella := mustLoadFeatures(t, "storage_block")
	assert.True(t, umbrella.StorageBlockFlush())
	assert.True(t, umbrella.StorageBlockDiscard())
	assert.True(t, umbrella.StorageBlockReadWrite())

	for _, wildcard := range []string{"*", "all"} {
		f := mustLoadFeatures(t, wildcard)
		assert.True(t, f.StorageBlockFlush(), wildcard)
		assert.True(t, f.StorageBlockDiscard(), wildcard)
	}

	flush := mustLoadFeatures(t, "storage_block_flush")
	assert.True(t, flush.StorageBlockFlush())
	assert.False(t, flush.StorageBlockDiscard())
	assert.True(t, flush.StorageBlock(), "flushes need the block probes")
	assert.True(t, flush.StatMetrics(), "flushes ride the stats pipeline")
	assert.False(t, flush.StorageBlockReadWrite())

	discard := mustLoadFeatures(t, "storage_block_discard")
	assert.True(t, discard.StorageBlockDiscard())
	assert.False(t, discard.StorageBlockFlush())
	assert.True(t, discard.StorageBlock(), "discards need the block probes")
	assert.False(t, discard.StorageBlockReadWrite())

	for _, name := range []string{"storage_block_duration", "storage_block_io", "storage_block_queue", "storage_block_errors", "storage_block_queue_depth"} {
		f := mustLoadFeatures(t, name)
		assert.True(t, f.StorageBlockReadWrite(), name)
		assert.False(t, f.StorageBlockFlush(), name)
		assert.False(t, f.StorageBlockDiscard(), name)
	}
}

// The deprecated queue depth is outside the storage_block umbrella: it costs a
// counter shared by every CPU on the block path, so it is only paid for when
// asked for by name. Asked for alone, it still needs the block probes.
func TestStorageBlockQueueDepthFeatureParsing(t *testing.T) {
	var umbrella Features
	require.NoError(t, yaml.Unmarshal([]byte(`["storage_block"]`), &umbrella))
	assert.False(t, umbrella.StorageBlockQueueDepth())

	var queue Features
	require.NoError(t, yaml.Unmarshal([]byte(`["storage_block_queue"]`), &queue))
	assert.False(t, queue.StorageBlockQueueDepth())

	var depth Features
	require.NoError(t, yaml.Unmarshal([]byte(`["storage_block_queue_depth"]`), &depth))
	assert.True(t, depth.StorageBlockQueueDepth())
	assert.True(t, depth.StorageBlock(), "the queue depth needs the block probes")
	assert.True(t, depth.StatMetrics(), "the queue depth rides the stats pipeline")
	assert.False(t, depth.StorageBlockQueue())
	assert.False(t, depth.StorageBlockDuration())
	assert.Equal(t, []DeprecatedFeature{{Name: "storage_block_queue_depth"}}, depth.DeprecatedEnabled())
}

// "*" and "all" leave the deprecated queue depth out, so its shared counter and
// its deprecation notice only come when the flag is listed by name.
func TestStorageBlockQueueDepthNotInWildcard(t *testing.T) {
	deprecatedNames := func(f Features) []string {
		names := []string{}
		for _, d := range f.DeprecatedEnabled() {
			names = append(names, d.Name)
		}
		return names
	}

	for _, wildcard := range []string{`["*"]`, `["all"]`} {
		t.Run(wildcard, func(t *testing.T) {
			var f Features
			require.NoError(t, yaml.Unmarshal([]byte(wildcard), &f))
			assert.False(t, f.StorageBlockQueueDepth())
			assert.True(t, f.StorageBlock())
			assert.True(t, f.StorageBlockQueue())
			assert.NotContains(t, deprecatedNames(f), "storage_block_queue_depth")
			assert.False(t, f.InvalidSpanMetricsConfig())
		})
	}

	var text Features
	require.NoError(t, text.UnmarshalText([]byte("*")))
	assert.False(t, text.StorageBlockQueueDepth())

	var named Features
	require.NoError(t, yaml.Unmarshal([]byte(`["*", "storage_block_queue_depth"]`), &named))
	assert.True(t, named.StorageBlockQueueDepth())
	assert.Contains(t, deprecatedNames(named), "storage_block_queue_depth")
	assert.False(t, named.InvalidSpanMetricsConfig(), "still the wildcard, so the span formats resolve")

	out, err := yaml.Marshal(struct {
		Features Features `yaml:"features"`
	}{named})
	require.NoError(t, err)
	assert.Equal(t, "features:\n    - all\n    - storage_block_queue_depth\n", string(out))
}

func TestStorageFSFeatureParsing(t *testing.T) {
	var f Features
	require.NoError(t, yaml.Unmarshal([]byte(`["storage_fs"]`), &f))
	assert.True(t, f.StorageFS())
	assert.True(t, f.StorageFSDuration())
	assert.True(t, f.StorageFSIo())
	assert.True(t, f.StorageFSErrors())
	assert.True(t, f.StatMetrics(), "storage_fs rides the stats pipeline")

	var d Features
	require.NoError(t, yaml.Unmarshal([]byte(`["storage_fs_duration"]`), &d))
	assert.True(t, d.StorageFS())
	assert.False(t, d.StorageFSIo())
	assert.False(t, d.StorageFSErrors())

	var e Features
	require.NoError(t, yaml.Unmarshal([]byte(`["storage_fs_errors"]`), &e))
	assert.True(t, e.StorageFS())
	assert.True(t, e.StorageFSErrors())
	assert.False(t, e.StorageFSDuration())
	assert.False(t, e.StorageFSIo())
}

func TestStorageNFSFeatureParsing(t *testing.T) {
	var f Features
	require.NoError(t, yaml.Unmarshal([]byte(`["storage_nfs"]`), &f))
	assert.True(t, f.StorageNFS())
	assert.True(t, f.StorageNFSDuration())
	assert.True(t, f.StorageNFSErrors())
	assert.True(t, f.StorageNFSRetransmits())
	assert.True(t, f.StatMetrics(), "storage_nfs rides the stats pipeline")
	assert.False(t, f.StorageFS(), "storage_nfs does not imply the filesystem metrics")

	var e Features
	require.NoError(t, yaml.Unmarshal([]byte(`["storage_nfs_errors"]`), &e))
	assert.True(t, e.StorageNFS())
	assert.True(t, e.StorageNFSErrors())
	assert.False(t, e.StorageNFSDuration())
	assert.False(t, e.StorageNFSRetransmits())

	var fs Features
	require.NoError(t, yaml.Unmarshal([]byte(`["storage_fs"]`), &fs))
	assert.False(t, fs.StorageNFS(), "storage_fs does not imply the NFS RPC metrics")
}

func TestFeatureUndefined(t *testing.T) {
	t.Run("undefined YAML", func(t *testing.T) {
		doc := struct {
			Features Features
		}{}
		require.NoError(t,
			yaml.Unmarshal([]byte(`{}`), &doc))
		require.False(t, doc.Features.Empty())
		require.True(t, doc.Features.Undefined())
	})
	t.Run("undefined env", func(t *testing.T) {
		doc := struct {
			Features Features `env:"FOO"`
		}{}
		require.NoError(t, env.Parse(&doc))
		require.False(t, doc.Features.Empty())
		require.True(t, doc.Features.Undefined())
	})
}

func TestFeatureMarshalYAML(t *testing.T) {
	type doc struct {
		Features Features `yaml:"features"`
	}
	for _, tc := range []struct {
		name     string
		features Features
		expected string
	}{
		{name: "undefined", features: 0, expected: "features: null\n"},
		{name: "explicitly empty", features: FeatureEmpty, expected: "features: []\n"},
		{
			name:     "single feature",
			features: FeatureApplicationRuntime,
			expected: "features:\n    - application_runtime\n",
		},
		{
			name:     "combined features follow the declaration order",
			features: FeatureApplicationRuntime | FeatureApplicationRED,
			expected: "features:\n    - application_red\n    - application_runtime\n",
		},
		{
			name:     "the application bundle keeps its name",
			features: FeatureApplicationRED | FeatureApplicationSizes,
			expected: "features:\n    - application\n",
		},
		{
			name:     "aggregate feature keeps its name",
			features: FeatureStats,
			expected: "features:\n    - stats\n",
		},
		{
			name:     "aggregate name comes before the remaining single features",
			features: FeatureStats | FeatureNetwork,
			expected: "features:\n    - stats\n    - network\n",
		},
		{
			name:     "partial aggregate expands to its bits",
			features: FeatureStatsTCPRtt | FeatureStatsTCPRetransmits,
			expected: "features:\n    - stats_tcp_rtt\n    - stats_tcp_retransmits\n",
		},
		{name: "all features", features: FeatureAll, expected: "features:\n    - all\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := yaml.Marshal(doc{Features: tc.features})
			require.NoError(t, err)
			require.Equal(t, tc.expected, string(out))

			var reparsed doc
			require.NoError(t, yaml.Unmarshal(out, &reparsed))
			require.Equal(t, tc.features, reparsed.Features)
		})
	}
}
