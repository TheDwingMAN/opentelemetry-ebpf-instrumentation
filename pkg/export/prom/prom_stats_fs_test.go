// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/connector"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

// newFsStatsReporter builds a stats reporter wired to an isolated registry
// with only the storage_fs feature enabled.
func newFsStatsReporter(t *testing.T, registry *prometheus.Registry) *statMetricsReporter {
	t.Helper()
	return newStatsReporterWithFeatures(t, registry, export.FeatureStorageFS)
}

// fsIoStat is one completed filesystem request: 64 KiB written to NFS
// taking 2ms.
func fsIoStat() *ebpf.Stat {
	return &ebpf.Stat{
		Type: ebpf.StatTypeFsIo,
		FsIo: &ebpf.FsIo{
			Fs:        uint8(ebpf.CodeFsNFS),
			Op:        uint8(ebpf.CodeFsOpWrite),
			LatencyNs: 2_000_000,
			Bytes:     65536,
		},
	}
}

// fsIoErrorStat is a failed filesystem completion on the same fs
// type/operation as fsIoStat, with a non-zero error (-ESTALE).
func fsIoErrorStat() *ebpf.Stat {
	return &ebpf.Stat{
		Type: ebpf.StatTypeFsIo,
		FsIo: &ebpf.FsIo{
			Fs:    uint8(ebpf.CodeFsNFS),
			Op:    uint8(ebpf.CodeFsOpWrite),
			Error: -116, // -ESTALE
		},
	}
}

// TestStatsReporterRecordsFsMetrics asserts that a single filesystem I/O event
// feeds both fs metric families -- the latency histogram and the bytes
// counter -- with the fs type and operation labels decoded from the raw stat.
func TestStatsReporterRecordsFsMetrics(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := newFsStatsReporter(t, registry)

	reporter.observeFsOpDuration(fsIoStat())
	reporter.observeFsIOBytes(fsIoStat())

	fsLabels := map[string]string{
		"system_filesystem_type": "nfs",
		"fs_operation":           "write",
		// The step 10 fs join labels: "" because fsIoStat carries no Mount
		// to resolve them from.
		"system_device":            "",
		"obi_disk_physical_device": "",
		"server_address":           "",
	}

	latency := gatheredMetric(t, registry, "obi_stat_fs_operation_duration_seconds", fsLabels)
	require.NotNil(t, latency, "latency histogram not registered or not observed")
	assert.Equal(t, uint64(1), latency.GetHistogram().GetSampleCount())
	assert.InEpsilon(t, 0.002, latency.GetHistogram().GetSampleSum(), 0.0001)

	ioBytes := gatheredMetric(t, registry, "obi_stat_fs_io_bytes_total", fsLabels)
	require.NotNil(t, ioBytes, "bytes counter not registered or not observed")
	assert.InEpsilon(t, 65536.0, ioBytes.GetCounter().GetValue(), 0)
}

// TestStatsReporterFsIOBytesSkipsZeroBytes asserts a completion that carries
// no bytes (an fsync success, or a queued/interrupted read/write with
// Bytes == 0) does not touch the counter at all rather than adding a zero
// increment for that label set.
func TestStatsReporterFsIOBytesSkipsZeroBytes(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := newFsStatsReporter(t, registry)

	fsyncStat := &ebpf.Stat{
		Type: ebpf.StatTypeFsIo,
		FsIo: &ebpf.FsIo{
			Fs:        uint8(ebpf.CodeFsNFS),
			Op:        uint8(ebpf.CodeFsOpFsync),
			LatencyNs: 1_000_000,
			Bytes:     0,
		},
	}

	reporter.observeFsIOBytes(fsyncStat)

	fsyncLabels := map[string]string{
		"system_filesystem_type": "nfs",
		"fs_operation":           "fsync",
	}
	ioBytes := gatheredMetric(t, registry, "obi_stat_fs_io_bytes_total", fsyncLabels)
	assert.Nil(t, ioBytes, "zero-byte completion must not create a bytes series")
}

// TestStatsReporterFsMetricsNotRegisteredWithoutFeature asserts the fs
// families are not registered at all when storage_fs is off, so enabling only
// TCP stats does not silently emit empty fs series.
func TestStatsReporterFsMetricsNotRegisteredWithoutFeature(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter, err := newStatsReporter(
		&global.ContextInfo{Prometheus: &connector.PrometheusManager{}},
		&StatsPrometheusConfig{
			Config:      &PrometheusConfig{Registry: registry, TTL: time.Minute},
			SelectorCfg: &attributes.SelectorConfig{},
			CommonCfg:   &perapp.GlobalMetricsConfig{Features: export.FeatureStatsTCPRtt},
		},
		msg.NewQueue[[]*ebpf.Stat](msg.ChannelBufferLen(1)),
	)
	require.NoError(t, err)

	assert.Nil(t, reporter.fsOpDuration)
	assert.Nil(t, reporter.fsIOBytes)
	assert.Nil(t, reporter.fsOpErrors)

	// Observing is a no-op rather than a nil-pointer panic.
	reporter.observeFsOpDuration(fsIoStat())
	reporter.observeFsIOBytes(fsIoStat())
	reporter.observeFsOpErrors(fsIoErrorStat())

	families, err := registry.Gather()
	require.NoError(t, err)
	for _, f := range families {
		assert.NotContains(t, f.GetName(), "fs_io")
		assert.NotContains(t, f.GetName(), "fs_operation")
	}
}

// TestStatsReporterRecordsFsOperationErrors asserts the error counter only
// increments for a failed filesystem completion, keyed by the errno name, and
// a successful completion (Error == 0) leaves it untouched.
func TestStatsReporterRecordsFsOperationErrors(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := newStatsReporterWithFeatures(t, registry, export.FeatureStorageFSErrors)

	reporter.observeFsOpErrors(fsIoStat()) // Error == 0: must not count
	reporter.observeFsOpErrors(fsIoErrorStat())

	opErrors := gatheredMetric(t, registry, "obi_stat_fs_operation_errors_total", map[string]string{
		"system_filesystem_type":   "nfs",
		"fs_operation":             "write",
		"error_type":               "ESTALE",
		"system_device":            "",
		"obi_disk_physical_device": "",
		"server_address":           "",
	})
	require.NotNil(t, opErrors, "errors counter not registered or not observed")
	assert.InEpsilon(t, 1.0, opErrors.GetCounter().GetValue(), 0)
}

// TestStatsReporterFsFeatureGating asserts each fs metric is independently
// selectable, mirroring TestStatsReporterDiskQueueAndErrorsFeatureGating for
// the disk errors counter.
func TestStatsReporterFsFeatureGating(t *testing.T) {
	for _, tc := range []struct {
		name        string
		features    export.Features
		wantLatency bool
		wantErrors  bool
	}{
		{"umbrella enables both", export.FeatureStorageFS, true, true},
		{"duration only", export.FeatureStorageFSDuration, true, false},
		{"errors only", export.FeatureStorageFSErrors, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			registry := prometheus.NewRegistry()
			reporter := newStatsReporterWithFeatures(t, registry, tc.features)

			reporter.observeFsOpDuration(fsIoStat())
			reporter.observeFsOpErrors(fsIoErrorStat())

			fsLabels := map[string]string{
				"system_filesystem_type":   "nfs",
				"fs_operation":             "write",
				"system_device":            "",
				"obi_disk_physical_device": "",
				"server_address":           "",
			}
			latency := gatheredMetric(t, registry, "obi_stat_fs_operation_duration_seconds", fsLabels)

			opErrors := gatheredMetric(t, registry, "obi_stat_fs_operation_errors_total", map[string]string{
				"system_filesystem_type":   "nfs",
				"fs_operation":             "write",
				"error_type":               "ESTALE",
				"system_device":            "",
				"obi_disk_physical_device": "",
				"server_address":           "",
			})

			assert.Equal(t, tc.wantLatency, latency != nil, "latency histogram presence")
			assert.Equal(t, tc.wantErrors, opErrors != nil, "errors counter presence")
		})
	}
}

// With Kubernetes metadata on, the fs metrics carry the pod and volume labels.
// The volume ones come from the mount the stat went through. An attribute
// that does not apply is the empty label value, which Prometheus stores as no
// label; the OTLP exporter leaves it out instead.
func TestStatsReporterFsKubeLabels(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter, err := newStatsReporter(
		&global.ContextInfo{Prometheus: &connector.PrometheusManager{}, MetricAttributeGroups: attributes.GroupKubernetes},
		&StatsPrometheusConfig{
			Config:      &PrometheusConfig{Registry: registry, TTL: time.Minute},
			SelectorCfg: &attributes.SelectorConfig{},
			CommonCfg:   &perapp.GlobalMetricsConfig{Features: export.FeatureStorageFS},
		},
		msg.NewQueue[[]*ebpf.Stat](msg.ChannelBufferLen(1)),
	)
	require.NoError(t, err)

	onVolume := fsIoStat()
	onVolume.CommonAttrs.Metadata = map[attr.Name]string{
		attr.K8sPodName: "writer", attr.K8sNamespaceName: "ns", attr.K8sContainerName: "io",
	}
	onVolume.FsIo.Mount = &ebpf.MountAttrs{PVName: "pvc-1", PVCName: "data", StorageClass: "fast", PVCNamespace: "ns"}
	reporter.observeFsOpDuration(onVolume)

	noVolume := fsIoStat()
	noVolume.FsIo.Fs = uint8(ebpf.CodeFsUnknown)
	reporter.observeFsOpDuration(noVolume)

	assert.NotNil(t, gatheredMetric(t, registry, "obi_stat_fs_operation_duration_seconds", map[string]string{
		"system_filesystem_type":         "nfs",
		"fs_operation":                   "write",
		"k8s_pod_name":                   "writer",
		"k8s_namespace_name":             "ns",
		"k8s_container_name":             "io",
		"k8s_persistentvolume_name":      "pvc-1",
		"k8s_persistentvolumeclaim_name": "data",
		"k8s_storageclass_name":          "fast",
		// k8s.owner.name, and the step 10 fs join labels, are unset by this
		// test's stat and mount fixtures.
		"k8s_owner_name":           "",
		"k8s_node_name":            "",
		"system_device":            "",
		"obi_disk_physical_device": "",
		"server_address":           "",
	}))
	assert.NotNil(t, gatheredMetric(t, registry, "obi_stat_fs_operation_duration_seconds", map[string]string{
		"system_filesystem_type":         "",
		"fs_operation":                   "write",
		"k8s_pod_name":                   "",
		"k8s_namespace_name":             "",
		"k8s_container_name":             "",
		"k8s_persistentvolume_name":      "",
		"k8s_persistentvolumeclaim_name": "",
		"k8s_storageclass_name":          "",
		"k8s_owner_name":                 "",
		"k8s_node_name":                  "",
		"system_device":                  "",
		"obi_disk_physical_device":       "",
		"server_address":                 "",
	}), "an unknown filesystem has no type label, not \"unknown\"")
}

// The mount paths are opt-in: absent by default, labels once selected, and
// the empty label for a stat that has none.
func TestStatsReporterFsMountpointLabelsAreOptIn(t *testing.T) {
	newReporter := func(registry *prometheus.Registry, include ...string) *statMetricsReporter {
		sel := attributes.Selection{}
		if include != nil {
			sel[attributes.StatFsOperationDuration.Section] = attributes.InclusionLists{Include: include}
			sel.Normalize()
		}
		reporter, err := newStatsReporter(
			&global.ContextInfo{Prometheus: &connector.PrometheusManager{}, MetricAttributeGroups: attributes.GroupKubernetes},
			&StatsPrometheusConfig{
				Config:      &PrometheusConfig{Registry: registry, TTL: time.Minute},
				SelectorCfg: &attributes.SelectorConfig{SelectionCfg: sel},
				CommonCfg:   &perapp.GlobalMetricsConfig{Features: export.FeatureStorageFS},
			},
			msg.NewQueue[[]*ebpf.Stat](msg.ChannelBufferLen(1)),
		)
		require.NoError(t, err)
		return reporter
	}
	stat := fsIoStat()
	stat.FsIo.Mount = &ebpf.MountAttrs{PVName: "pvc-1", HostPath: "/var/lib/kubelet/pods/u/volumes/kubernetes.io~csi/pvc-1/mount", ContainerPath: "/data"}

	defaults := map[string]string{
		"system_filesystem_type":         "nfs",
		"fs_operation":                   "write",
		"k8s_pod_name":                   "",
		"k8s_namespace_name":             "",
		"k8s_container_name":             "",
		"k8s_persistentvolume_name":      "pvc-1",
		"k8s_persistentvolumeclaim_name": "",
		"k8s_storageclass_name":          "",
		"k8s_owner_name":                 "",
		"k8s_node_name":                  "",
		"system_device":                  "",
		"obi_disk_physical_device":       "",
		"server_address":                 "",
	}
	const name = "obi_stat_fs_operation_duration_seconds"

	off := prometheus.NewRegistry()
	newReporter(off).observeFsOpDuration(stat)
	assert.NotNil(t, gatheredMetric(t, off, name, defaults), "no mount path label by default")

	on := prometheus.NewRegistry()
	newReporter(on, "system_filesystem_mountpoint", "obi_fs_container_mountpoint", "fs_operation", "k8s_persistentvolume_name").
		observeFsOpDuration(stat)
	assert.NotNil(t, gatheredMetric(t, on, name, map[string]string{
		"system_filesystem_mountpoint": stat.FsIo.Mount.HostPath,
		"obi_fs_container_mountpoint":  "/data",
		"fs_operation":                 "write",
		"k8s_persistentvolume_name":    "pvc-1",
	}))
}
