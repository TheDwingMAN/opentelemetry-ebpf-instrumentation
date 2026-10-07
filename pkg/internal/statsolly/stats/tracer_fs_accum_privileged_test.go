// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package stats

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
)

// kubeletVolume makes an ext4 filesystem on a loop device and mounts it where
// the kubelet mounts a CSI volume, so the filesystem probes attach to it.
func kubeletVolume(t *testing.T) string {
	t.Helper()
	for _, tool := range []string{"losetup", "mkfs.ext4"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("no %s", tool)
		}
	}
	backing := filepath.Join(t.TempDir(), "backing")
	require.NoError(t, os.WriteFile(backing, nil, 0o600))
	require.NoError(t, os.Truncate(backing, 64<<20))
	out, err := exec.Command("losetup", "--find", "--show", backing).CombinedOutput()
	if err != nil {
		t.Skipf("no loop device: %v: %s", err, out)
	}
	loop := strings.TrimSpace(string(out))
	t.Cleanup(func() { _ = exec.Command("losetup", "--detach", loop).Run() })
	out, err = exec.Command("mkfs.ext4", "-q", "-F", loop).CombinedOutput()
	require.NoError(t, err, "mkfs.ext4: %s", out)

	pod := "/var/lib/kubelet/pods/0b1f5e0a-0000-4000-8000-00000000e2e7"
	mountPoint := filepath.Join(pod, "volumes/kubernetes.io~csi/pv-e2e/mount")
	require.NoError(t, os.MkdirAll(mountPoint, 0o755))
	t.Cleanup(func() { os.RemoveAll(pod) })
	require.NoError(t, unix.Mount(loop, mountPoint, "ext4", 0, ""))
	t.Cleanup(func() { _ = unix.Unmount(mountPoint, 0) })
	return mountPoint
}

// The whole kernel aggregation path on a real kernel: the stats fetcher
// loads the filesystem programs in AGG mode, they count writes and an fsync
// on a kubelet volume into fs_io_accum, and the filesystem family reads that
// map through statagg.MapSource into the Prometheus collector, with exactly
// the operations, bytes and bucket counts the process did.
func TestFsAccumFamilyReadsTheKernelMap(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load eBPF programs and mount filesystems")
	}
	const (
		writes     = 40
		writeBytes = 8192
	)
	dir := kubeletVolume(t)

	layout, err := statagg.NewExplicitLayout(export.DefaultBuckets.StatFsOperationDurationHistogram)
	require.NoError(t, err)
	features := export.FeatureStorageFS
	fetcher, err := ebpf.NewStatsFetcher(&config.EBPFTracer{}, &features, &attributes.SelectorConfig{},
		ebpf.FsAggregation{Enabled: true, BoundsNs: layout.KernelBounds()}, ebpf.NFSConfig{}, nil, nil)
	require.NoError(t, err)
	t.Cleanup(func() { fetcher.Close() })
	require.NotNil(t, fetcher.FsAccumMap(), "the aggregation map exists in AGG mode")

	source, err := statagg.NewMapSource(fetcher.FsAccumMap())
	require.NoError(t, err)
	family, err := NewFsAccumFamily(FsAccum{Source: source, Layout: layout})
	require.NoError(t, err)
	registry, err := statagg.NewRegistry(family)
	require.NoError(t, err)
	collector := benchCollector(t, registry, layout)
	go family.Run(t.Context())

	f, err := os.Create(filepath.Join(dir, "data"))
	require.NoError(t, err)
	block := make([]byte, writeBytes)
	for i := range writes {
		_, err := unix.Pwrite(int(f.Fd()), block, int64(i*writeBytes))
		require.NoError(t, err)
	}
	require.NoError(t, f.Sync())
	require.NoError(t, f.Close())

	type sample struct{ bytes, ops, sumOps uint64 }
	scrape := func() map[string]*sample {
		ch := make(chan prometheus.Metric, 64)
		collector.Collect(ch)
		close(ch)
		got := map[string]*sample{}
		for m := range ch {
			var pb dto.Metric
			require.NoError(t, m.Write(&pb))
			var fsType, op string
			for _, l := range pb.GetLabel() {
				switch l.GetName() {
				case "system_filesystem_type":
					fsType = l.GetValue()
				case "fs_operation":
					op = l.GetValue()
				}
			}
			if fsType != "ext4" {
				continue
			}
			s := got[op]
			if s == nil {
				s = &sample{}
				got[op] = s
			}
			if c := pb.GetCounter(); c != nil {
				s.bytes += uint64(c.GetValue())
			}
			if h := pb.GetHistogram(); h != nil {
				s.ops += h.GetSampleCount()
				buckets := h.GetBucket()
				if n := len(buckets); n > 0 {
					// cumulative: the last classic bucket below +Inf, plus
					// the overflow, is every sample.
					s.sumOps = buckets[n-1].GetCumulativeCount()
				}
			}
		}
		return got
	}

	var got map[string]*sample
	require.Eventually(t, func() bool {
		got = scrape()
		return got["write"] != nil && got["write"].ops >= writes && got["fsync"] != nil && got["fsync"].ops >= 1
	}, 10*time.Second, 100*time.Millisecond)
	// Only this test writes to the volume: the counts are exact.
	assert.Equal(t, uint64(writes), got["write"].ops)
	assert.Equal(t, uint64(writes*writeBytes), got["write"].bytes)
	assert.Equal(t, uint64(1), got["fsync"].ops)
	assert.Zero(t, got["fsync"].bytes, "fsync counts no bytes")
	assert.LessOrEqual(t, got["write"].sumOps, got["write"].ops)
}
