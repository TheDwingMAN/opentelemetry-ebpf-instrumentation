// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package export // import "go.opentelemetry.io/obi/pkg/export"

import (
	"cmp"
	"fmt"
	"math/bits"
	"slices"
	"strings"

	"github.com/invopop/jsonschema"
	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/pkg/internal/helpers/maps"
)

// Features is a bitmask of enabled metric features.
// Each Features value can contain data about a single feature or a combination of OR-ed features.
type Features maps.Bits

const (
	// FeatureEmpty is a special value that can be used to indicate that a feature list has been explicitly
	// set to an empty list (e.g. [] in YAML), as opposed to the undefined value, which would correspond to the
	// zero value.
	FeatureEmpty Features = 1 << iota
	FeatureNetwork
	FeatureNetworkFlowPackets
	FeatureStatsTCPRtt
	FeatureStatsTCPFailedConnections
	FeatureStatsTCPSuccessfulConnections
	FeatureStatsTCPRetransmits
	FeatureStatsTCPIo
	FeatureNetworkInterZone
	FeatureApplicationRED
	// FeatureApplicationSizes emits the HTTP request and response body size histograms.
	// The semantic conventions mark them Opt-In while the RED duration histograms are
	// Recommended, so they are a bit of their own. The "application" name keeps enabling
	// both, and "application_red" selects the RED metrics without them.
	FeatureApplicationSizes
	// FeatureSpanLegacy emits span metrics under the Grafana-convention
	// traces_spanmetrics_* names.
	//
	// Deprecated: use FeatureSpanOTel, which emits the traces_span_metrics_* names of
	// the OTel collector-contrib spanmetrics connector.
	FeatureSpanLegacy
	FeatureSpanOTel
	// FeatureSpanSizes emits the request and response size counters of the same
	// Grafana-convention traces_spanmetrics_* family as FeatureSpanLegacy.
	//
	// Deprecated: there is no OTel-named equivalent; the semantic-convention
	// http.server.request.body.size and http.server.response.body.size metrics are the
	// closest replacement, but they are HTTP-specific and not keyed by span.
	FeatureSpanSizes
	FeatureGraph
	FeatureApplicationRuntime
	FeatureEBPF
	FeatureStorageBlockDuration
	FeatureStorageBlockIo
	FeatureStorageBlockQueue
	FeatureStorageBlockErrors
	FeatureStorageFSDuration
	FeatureStorageFSIo
	FeatureStorageFSErrors
	// FeatureStorageBlockQueueDepth emits the per-completion in-flight histogram
	// obi.stat.disk.queue.depth. It is in no umbrella: it is the only block metric
	// that needs a counter shared by every CPU on the block path.
	//
	// Deprecated: the metric will be removed.
	FeatureStorageBlockQueueDepth
	FeatureStorageBlockFlush
	FeatureStorageBlockDiscard
	// FeatureStorageNFSDuration, FeatureStorageNFSErrors,
	// FeatureStorageNFSRetransmits and FeatureStorageNFSIo emit the NFS
	// client RPC metrics, counted in the kernel from the sunrpc
	// rpc_stats_latency tracepoint.
	FeatureStorageNFSDuration
	FeatureStorageNFSErrors
	FeatureStorageNFSRetransmits
	FeatureStorageNFSIo
	// FeatureStorageFSSync enables the storage_fs_sync probes: fentry/fexit
	// (kprobe fallback) on the syncfs and sync_file_range syscall wrappers,
	// kprobe/kretprobe on the sync wrapper (step 14). Unlike
	// FeatureStorageFSDuration/Io/Errors, which only split series
	// cardinality on an already-running probe pair, this is its own probe
	// set: disabling it stops the kernel-side work, not just the export.
	FeatureStorageFSSync
	// FeatureAll is what "all" and "*" select: every feature except the deprecated
	// FeatureStorageBlockQueueDepth, which is in no umbrella and is only enabled
	// when listed by name.
	FeatureAll = Features(^uint(0)) &^ FeatureStorageBlockQueueDepth
)

// FeatureStorageBlock enables all block-layer storage metrics.
// Note: the block tracepoints (block_rq_insert, block_rq_issue,
// block_rq_complete) attach together whenever any storage_block* bit is set,
// and every request pays for them. Disabling duration/io/queue/errors only
// reduces series cardinality: their read and write events are delivered as
// long as one of them is on. Flushes and discards are the exception: without
// storage_block_flush or storage_block_discard their completions end in the
// kernel, without a ring buffer event.
const FeatureStorageBlock = FeatureStorageBlockDuration | FeatureStorageBlockIo | FeatureStorageBlockQueue | FeatureStorageBlockErrors |
	FeatureStorageBlockFlush | FeatureStorageBlockDiscard

// FeatureStorageFS enables all filesystem metrics. Duration/Io/Errors derive
// from the same probe pair, so disabling one of those does not reduce
// kernel-side overhead — splitting them controls series cardinality only.
// Sync is its own probe set (step 14): the umbrella enables it too, but it
// can also be disabled on its own without losing read/write/fsync.
const FeatureStorageFS = FeatureStorageFSDuration | FeatureStorageFSIo | FeatureStorageFSErrors | FeatureStorageFSSync

// FeatureStorageNFS enables all NFS client RPC metrics. They share one
// program on the sunrpc rpc_stats_latency tracepoint, which runs once per NFS
// RPC attempt: disabling one of them reduces series cardinality, and only
// storage_nfs_errors adds kernel keys (one per error status); storage_nfs_io
// reads two more words of the same key. It is its own umbrella: storage_fs
// does not imply it.
const FeatureStorageNFS = FeatureStorageNFSDuration | FeatureStorageNFSErrors | FeatureStorageNFSRetransmits | FeatureStorageNFSIo

// FeatureStats enables all stat metrics, including TCP IO.
// Note: FeatureStatsTCPIo fires on every tcp_sendmsg and tcp_cleanup_rbuf call — significantly
// higher event volume than the other stat metrics (which fire on close, failure, or retransmit).
// If overhead is a concern, enable the lower-frequency metrics individually and opt into stats_tcp_io explicitly.
const FeatureStats = FeatureStatsTCPRtt | FeatureStatsTCPFailedConnections | FeatureStatsTCPRetransmits | FeatureStatsTCPIo | FeatureStatsTCPSuccessfulConnections

// FeatureMapper stays public so any extension package can add and remove feature
// definitions before loading them.
var FeatureMapper = map[string]Features{
	"stats":                            FeatureStats,
	"stats_tcp_rtt":                    FeatureStatsTCPRtt,
	"stats_tcp_failed_connections":     FeatureStatsTCPFailedConnections,
	"stats_tcp_retransmits":            FeatureStatsTCPRetransmits,
	"stats_tcp_io":                     FeatureStatsTCPIo,
	"stats_tcp_successful_connections": FeatureStatsTCPSuccessfulConnections,
	"storage_block":                    FeatureStorageBlock,
	"storage_block_duration":           FeatureStorageBlockDuration,
	"storage_block_io":                 FeatureStorageBlockIo,
	"storage_block_queue":              FeatureStorageBlockQueue,
	"storage_block_errors":             FeatureStorageBlockErrors,
	"storage_block_flush":              FeatureStorageBlockFlush,
	"storage_block_discard":            FeatureStorageBlockDiscard,
	"storage_block_queue_depth":        FeatureStorageBlockQueueDepth,
	"storage_fs":                       FeatureStorageFS,
	"storage_fs_duration":              FeatureStorageFSDuration,
	"storage_fs_io":                    FeatureStorageFSIo,
	"storage_fs_errors":                FeatureStorageFSErrors,
	"storage_nfs":                      FeatureStorageNFS,
	"storage_nfs_duration":             FeatureStorageNFSDuration,
	"storage_nfs_errors":               FeatureStorageNFSErrors,
	"storage_nfs_retransmits":          FeatureStorageNFSRetransmits,
	"storage_nfs_io":                   FeatureStorageNFSIo,
	"storage_fs_sync":                  FeatureStorageFSSync,
	"network":                          FeatureNetwork,
	"network_inter_zone":               FeatureNetworkInterZone,
	"network_flow_packets":             FeatureNetworkFlowPackets,
	"application":                      FeatureApplicationRED | FeatureApplicationSizes,
	"application_red":                  FeatureApplicationRED,
	"application_sizes":                FeatureApplicationSizes,
	"application_span":                 FeatureSpanLegacy,
	"application_span_otel":            FeatureSpanOTel,
	"application_span_sizes":           FeatureSpanSizes,
	"application_service_graph":        FeatureGraph,
	"application_runtime":              FeatureApplicationRuntime,
	"ebpf":                             FeatureEBPF,
	"all":                              FeatureAll,
	"*":                                FeatureAll,
}

// deprecatedFeatures maps each deprecated feature name to the feature that supersedes it.
// An empty replacement means the feature is going away without a direct equivalent.
// The names keep working; they are reported at startup and flagged as deprecated in the
// generated JSON schema and configuration reference.
var deprecatedFeatures = map[string]string{
	"application_span":          "application_span_otel",
	"application_span_sizes":    "",
	"storage_block_queue_depth": "",
}

// DeprecatedFeature is a deprecated feature name together with the feature that
// supersedes it. Replacement is empty when there is no direct equivalent.
type DeprecatedFeature struct {
	Name        string
	Replacement string
}

// deprecatedFeatureNames returns the deprecated feature names, sorted.
func deprecatedFeatureNames() []string {
	names := make([]string, 0, len(deprecatedFeatures))
	for name := range deprecatedFeatures {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// DeprecatedEnabled returns the deprecated features enabled in f, sorted by name.
func (f Features) DeprecatedEnabled() []DeprecatedFeature {
	enabled := make([]DeprecatedFeature, 0, len(deprecatedFeatures))
	for _, name := range deprecatedFeatureNames() {
		if f.any(FeatureMapper[name]) {
			enabled = append(enabled, DeprecatedFeature{Name: name, Replacement: deprecatedFeatures[name]})
		}
	}
	return enabled
}

// deprecatedSchemaDescription documents each deprecated value and its replacement, so the
// generated schema and configuration reference name the migration target directly.
func deprecatedSchemaDescription() string {
	migrations := make([]string, 0, len(deprecatedFeatures))
	for _, name := range deprecatedFeatureNames() {
		if replacement := deprecatedFeatures[name]; replacement != "" {
			migrations = append(migrations, fmt.Sprintf("%s (use %s)", name, replacement))
			continue
		}
		migrations = append(migrations, name+" (no direct replacement)")
	}
	return "Deprecated feature names, kept for backwards compatibility: " +
		strings.Join(migrations, ", ") + "."
}

func (Features) JSONSchema() *jsonschema.Schema {
	names := validFeatureNames()
	supported := make([]any, 0, len(names)+1)
	deprecated := make([]any, 0, len(deprecatedFeatures))
	for _, name := range names {
		if _, ok := deprecatedFeatures[name]; ok {
			deprecated = append(deprecated, name)
			continue
		}
		supported = append(supported, name)
	}
	supported = append(supported, "*")
	return &jsonschema.Schema{
		Type: "array",
		Items: &jsonschema.Schema{
			OneOf: []*jsonschema.Schema{
				{
					Type: "string",
					Enum: supported,
				},
				{
					Type:        "string",
					Enum:        deprecated,
					Deprecated:  true,
					Description: deprecatedSchemaDescription(),
				},
			},
		},
		Description: "List of metric features to enable.",
	}
}

// AppO11yFeatures is a bitmask of all metrics that are enabled by default for Application RED
// It can be overridden by extension packages
var AppO11yFeatures = FeatureApplicationRED |
	FeatureApplicationSizes |
	FeatureSpanLegacy |
	FeatureSpanOTel |
	FeatureSpanSizes |
	FeatureGraph

func validFeatureNames() []string {
	names := make([]string, 0, len(FeatureMapper))
	for name := range FeatureMapper {
		if name == "*" {
			continue
		}
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// marshalNames returns the enabled feature names: aggregate names (e.g. "all", "stats")
// when all of their bits are enabled, then the remaining single-bit names in declaration order.
func (f Features) marshalNames() []string {
	singles := make([]string, 0, len(FeatureMapper))
	aggregates := make([]string, 0, len(FeatureMapper))
	for name, feature := range FeatureMapper {
		// FeatureAll is emitted under its "all" alias
		if name == "*" {
			continue
		}
		if bits.OnesCount(uint(feature)) == 1 {
			singles = append(singles, name)
		} else {
			aggregates = append(aggregates, name)
		}
	}
	// widest aggregate first, so "all" wins over "stats" when both apply
	slices.SortFunc(aggregates, func(a, b string) int {
		return bits.OnesCount(uint(FeatureMapper[b])) - bits.OnesCount(uint(FeatureMapper[a]))
	})
	slices.SortFunc(singles, func(a, b string) int {
		return cmp.Compare(FeatureMapper[a], FeatureMapper[b])
	})

	names := make([]string, 0, len(singles))
	remaining := f
	for _, name := range slices.Concat(aggregates, singles) {
		feature := FeatureMapper[name]
		if remaining.has(feature) {
			names = append(names, name)
			remaining = Features(maps.Bits(remaining) &^ maps.Bits(feature))
		}
	}
	return names
}

// MarshalYAML renders the bitmask as the list of enabled feature names, so a logged
// configuration shows the same values that can be written in the YAML.
func (f Features) MarshalYAML() (any, error) {
	if f.Undefined() {
		return nil, nil
	}
	// an empty sequence, in opposition of "null" in the undefined case
	node := yaml.Node{Kind: yaml.SequenceNode}
	for _, name := range f.marshalNames() {
		node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: name})
	}
	return node, nil
}

func LoadFeatures(features []string) (Features, error) {
	if len(features) == 0 {
		return FeatureEmpty, nil
	}
	// convert the public data type to the internal representation
	feats := Features(0)
	for _, f := range features {
		name := strings.TrimSpace(f)
		if name == "" {
			continue
		}
		feature, ok := FeatureMapper[name]
		if !ok {
			return Features(0), fmt.Errorf("unknown metrics feature %q (valid features: %s)",
				name, strings.Join(validFeatureNames(), ", "))
		}
		feats |= feature
	}
	return feats, nil
}

func (f Features) has(feature Features) bool {
	return maps.Bits(f).Has(maps.Bits(feature))
}

func (f Features) any(feature Features) bool {
	return maps.Bits(f).Any(maps.Bits(feature))
}

func (f *Features) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.SequenceNode {
		return fmt.Errorf("feature: unexpected YAML node kind %v", value.Kind)
	}
	features := make([]string, 0, len(value.Content))
	for i, item := range value.Content {
		if item.Kind != yaml.ScalarNode {
			return fmt.Errorf("feature[%d]: unexpected YAML node kind %v (%v)",
				i, item.Kind, item.Value)
		}
		features = append(features, item.Value)
	}
	feats, err := LoadFeatures(features)
	if err != nil {
		return err
	}
	*f = feats
	return nil
}

func (f *Features) UnmarshalText(text []byte) error {
	feats, err := LoadFeatures(strings.Split(string(text), ","))
	if err != nil {
		return err
	}
	*f = feats
	return nil
}

func (f Features) Undefined() bool {
	return f == 0
}

func (f Features) Empty() bool {
	return f == FeatureEmpty
}

func (f Features) AnyAppO11yMetric() bool {
	return f.any(AppO11yFeatures | FeatureApplicationRuntime)
}

func (f Features) SpanMetrics() bool {
	return f.any(FeatureSpanLegacy | FeatureSpanOTel)
}

func (f Features) AnySpanMetrics() bool {
	return f.any(FeatureSpanLegacy | FeatureSpanOTel | FeatureSpanSizes)
}

func (f Features) AnyNetwork() bool {
	return f.any(FeatureNetwork | FeatureNetworkInterZone | FeatureNetworkFlowPackets)
}

func (f Features) AppOrSpan() bool {
	return f.any(FeatureApplicationRED |
		FeatureApplicationSizes |
		FeatureSpanSizes |
		FeatureApplicationRuntime |
		FeatureSpanLegacy |
		FeatureSpanOTel)
}

// LegacySpanMetrics reports whether FeatureSpanLegacy is enabled.
//
// Deprecated: kept only to keep emitting traces_spanmetrics_* while FeatureSpanLegacy
// still exists.
func (f Features) LegacySpanMetrics() bool {
	return f.any(FeatureSpanLegacy)
}

func (f Features) ServiceGraph() bool {
	return f.any(FeatureGraph)
}

func (f Features) AppRuntime() bool {
	return f.any(FeatureApplicationRuntime)
}

func (f Features) AppRED() bool {
	return f.any(FeatureApplicationRED)
}

// AppSizes reports whether the HTTP body size histograms are enabled. They are emitted
// from the HTTP application metrics pipeline, so AppRED must be enabled as well.
func (f Features) AppSizes() bool {
	return f.any(FeatureApplicationSizes)
}

func (f Features) SpanSizes() bool {
	return f.any(FeatureSpanSizes)
}

func (f Features) NetworkBytes() bool {
	return f.any(FeatureNetwork)
}

func (f Features) NetworkFlowPackets() bool {
	return f.any(FeatureNetworkFlowPackets)
}

func (f Features) StatMetrics() bool {
	return f.any(FeatureStats | FeatureStorageBlock | FeatureStorageBlockQueueDepth | FeatureStorageFS | FeatureStorageNFS)
}

func (f Features) StatsTCPRtt() bool {
	return f.any(FeatureStatsTCPRtt)
}

func (f Features) StatsTCPFailedConnections() bool {
	return f.any(FeatureStatsTCPFailedConnections)
}

func (f Features) StatsTCPSuccessfulConnections() bool {
	return f.any(FeatureStatsTCPSuccessfulConnections)
}

func (f Features) StatsTCPRetransmits() bool {
	return f.any(FeatureStatsTCPRetransmits)
}

func (f Features) StatsTCPIo() bool {
	return f.any(FeatureStatsTCPIo)
}

// StorageBlock reports whether any block-layer storage metric is enabled. It
// gates the shared setup (eBPF probes, ring buffer) that every block metric
// needs, including the deprecated queue depth outside the umbrella.
func (f Features) StorageBlock() bool {
	return f.any(FeatureStorageBlock | FeatureStorageBlockQueueDepth)
}

func (f Features) StorageBlockDuration() bool {
	return f.any(FeatureStorageBlockDuration)
}

func (f Features) StorageBlockIo() bool {
	return f.any(FeatureStorageBlockIo)
}

func (f Features) StorageBlockQueue() bool {
	return f.any(FeatureStorageBlockQueue)
}

func (f Features) StorageBlockErrors() bool {
	return f.any(FeatureStorageBlockErrors)
}

func (f Features) StorageBlockQueueDepth() bool {
	return f.any(FeatureStorageBlockQueueDepth)
}

// StorageBlockReadWrite reports whether any metric of block reads and writes is
// enabled, the ones that carry a disk.io.direction.
func (f Features) StorageBlockReadWrite() bool {
	return f.any(FeatureStorageBlockDuration | FeatureStorageBlockIo | FeatureStorageBlockQueue |
		FeatureStorageBlockErrors | FeatureStorageBlockQueueDepth)
}

func (f Features) StorageBlockFlush() bool {
	return f.any(FeatureStorageBlockFlush)
}

func (f Features) StorageBlockDiscard() bool {
	return f.any(FeatureStorageBlockDiscard)
}

// StorageFS reports whether any filesystem metric is enabled. It gates
// the shared setup (eBPF probes, ring buffer) that both metrics need.
func (f Features) StorageFS() bool {
	return f.any(FeatureStorageFS)
}

func (f Features) StorageFSDuration() bool {
	return f.any(FeatureStorageFSDuration)
}

func (f Features) StorageFSIo() bool {
	return f.any(FeatureStorageFSIo)
}

func (f Features) StorageFSErrors() bool {
	return f.any(FeatureStorageFSErrors)
}

// StorageNFS reports whether any NFS client RPC metric is enabled. It gates
// the NFS program and its kernel aggregation map.
func (f Features) StorageNFS() bool {
	return f.any(FeatureStorageNFS)
}

func (f Features) StorageNFSDuration() bool {
	return f.any(FeatureStorageNFSDuration)
}

func (f Features) StorageNFSErrors() bool {
	return f.any(FeatureStorageNFSErrors)
}

func (f Features) StorageNFSRetransmits() bool {
	return f.any(FeatureStorageNFSRetransmits)
}

func (f Features) StorageNFSIo() bool {
	return f.any(FeatureStorageNFSIo)
}

func (f Features) StorageFSSync() bool {
	return f.any(FeatureStorageFSSync)
}

func (f Features) NetworkInterZone() bool {
	return f.any(FeatureNetworkInterZone)
}

func (f Features) BPF() bool {
	return f.any(FeatureEBPF)
}

// InvalidSpanMetricsConfig is used to make sure that you can't define both legacy and OTEL span metrics at the same time.
// It returns false when FeatureAll is set (e.g. via "*" or "all"), because the user didn't explicitly
// pick both conflicting formats. In that case, the caller should resolve the conflict automatically.
func (f Features) InvalidSpanMetricsConfig() bool {
	return f.has(FeatureSpanLegacy|FeatureSpanOTel) && !f.has(FeatureAll)
}

// ResolveSpanMetricsConflict checks if both span metric formats are enabled (e.g. via "*" or "all")
// and resolves the conflict by disabling the legacy format in favor of OTel.
// Returns true if a resolution was applied.
func (f *Features) ResolveSpanMetricsConflict() bool {
	if f.has(FeatureSpanLegacy | FeatureSpanOTel) {
		*f = Features(maps.Bits(*f) &^ maps.Bits(FeatureSpanLegacy))
		return true
	}
	return false
}
