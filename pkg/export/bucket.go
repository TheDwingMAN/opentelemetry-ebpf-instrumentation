// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package export // import "go.opentelemetry.io/obi/pkg/export"

import (
	"math"
	"slices"
)

// Buckets defines the histograms bucket boundaries, and allows users to
// redefine them
type Buckets struct {
	DurationHistogram                  []float64 `yaml:"duration_histogram"`
	RequestSizeHistogram               []float64 `yaml:"request_size_histogram"`
	ResponseSizeHistogram              []float64 `yaml:"response_size_histogram"`
	GenAITokenUsageHistogram           []float64 `yaml:"gen_ai_client_token_usage_histogram"`
	GenAIClientDurationHistogram       []float64 `yaml:"gen_ai_client_operation_duration_histogram"`
	StatTCPRttHistogram                []float64 `yaml:"stat_tcp_rtt_histogram"`
	StatDiskOperationDurationHistogram []float64 `yaml:"stat_disk_operation_duration_histogram"`
	StatDiskQueueDepthHistogram        []float64 `yaml:"stat_disk_queue_depth_histogram"`
	StatFsOperationDurationHistogram   []float64 `yaml:"stat_fs_operation_duration_histogram"`
	V8JSGCDurationHistogram            []float64 `yaml:"v8js_gc_duration_histogram"`
	JVMGCDurationHistogram             []float64 `yaml:"jvm_gc_duration_histogram"`
	// StatNFSClientRPCDurationHistogram counts NFS client RPC attempts in the
	// kernel, whose explicit layout holds at most 32 bounds: the union of the
	// OTel and Prometheus bounds must fit in it.
	StatNFSClientRPCDurationHistogram []float64 `yaml:"stat_nfs_client_rpc_duration_histogram"`
}

// DefaultBuckets define the default explicit bucket boundaries. They are ignored by the OTEL exporter when
// histogram_aggregation=base2_exponential_bucket_histogram.
var DefaultBuckets = Buckets{
	// Default values as specified in the OTEL specification
	// https://opentelemetry.io/docs/specs/semconv/http/http-metrics/#metric-httpserverrequestduration
	DurationHistogram: []float64{0, 0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10},

	RequestSizeHistogram:  []float64{0, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192},
	ResponseSizeHistogram: []float64{0, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192},

	// https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-metrics/#metric-gen_aiclienttokenusage
	GenAITokenUsageHistogram: []float64{1, 4, 16, 64, 256, 1024, 4096, 16384, 65536, 262144, 1048576, 4194304, 16777216, 67108864},
	// https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-metrics/#metric-gen_aiclientoperationduration
	GenAIClientDurationHistogram: []float64{0.01, 0.02, 0.04, 0.08, 0.16, 0.32, 0.64, 1.28, 2.56, 5.12, 10.24, 20.48, 40.96, 81.92},

	// Covers sub-millisecond to low-second RTT range.
	StatTCPRttHistogram: []float64{0.0005, 0.001, 0.002, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.0},

	// Covers NVMe sub-millisecond service times up to saturated-device multi-second tails.
	StatDiskOperationDurationHistogram: []float64{0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.0, 2.5, 5.0},

	// Power-of-two queue depth buckets, from a single outstanding request up to
	// a deeply saturated device.
	StatDiskQueueDepthHistogram: []float64{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024},

	// Filesystem ops: sub-millisecond page-cache hits up to multi-second
	// stalls on a degraded server.
	StatFsOperationDurationHistogram: []float64{0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.0, 2.5, 5.0},

	// NFS client RPC attempts: the filesystem bounds plus 10 s. An attempt
	// that follows a server's NFSv3 JUKEBOX or NFSv4 DELAY includes the
	// client's backoff (5 s for JUKEBOX), which the filesystem bounds would
	// leave in +Inf.
	StatNFSClientRPCDurationHistogram: []float64{0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.0, 2.5, 5.0, 10.0},

	// https://opentelemetry.io/docs/specs/semconv/runtime/nodejs-metrics/#metric-v8jsgcduration
	V8JSGCDurationHistogram: []float64{0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10},

	// https://opentelemetry.io/docs/specs/semconv/runtime/jvm-metrics/#metric-jvmgcduration
	JVMGCDurationHistogram: []float64{0.01, 0.1, 1, 10},
}

// UnionBounds returns the sorted union of histogram bucket bounds, without
// duplicates. A kernel-side histogram that must serve several exporters, each
// with its own bounds, counts into this union: every exporter folds it back to
// its own bounds exactly, because they are a subset.
func UnionBounds(sets ...[]float64) []float64 {
	var union []float64
	for _, set := range sets {
		union = append(union, set...)
	}
	slices.Sort(union)
	return slices.Compact(union)
}

// Base2ExponentialBounds returns the bucket boundaries of a base-2 exponential
// histogram at scale, base^k with base = 2^(2^-scale), from the largest one <=
// lowest to the smallest one >= highest, and the index k of the first. These
// are the boundaries the OpenTelemetry base2_exponential_bucket_histogram and
// Prometheus native histograms (schema = scale) place their buckets on.
func Base2ExponentialBounds(scale int32, lowest, highest float64) (firstIndex int32, bounds []float64) {
	perOctave := math.Exp2(float64(scale))
	first := int32(math.Floor(math.Log2(lowest) * perOctave))
	last := int32(math.Ceil(math.Log2(highest) * perOctave))
	bounds = make([]float64, 0, last-first+1)
	for k := first; k <= last; k++ {
		bounds = append(bounds, math.Exp2(float64(k)/perOctave))
	}
	return first, bounds
}
