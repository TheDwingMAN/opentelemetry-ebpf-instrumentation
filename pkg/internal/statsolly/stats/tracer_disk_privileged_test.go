// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package stats

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

const (
	loopBackingFileSize = 64 << 20
	directIOBlockSize   = 64 << 10
	directIOBlocks      = 256
)

// TestDiskLatencyIsAccumulatedPerDevice drives a known I/O pattern on a loop device and checks
// that the kernel accumulates exactly one latency sample per completed request. The I/O is
// O_DIRECT and sequential at queue depth 1, so the block layer neither caches nor merges it.
func TestDiskLatencyIsAccumulatedPerDevice(t *testing.T) {
	bounds := []float64{0.001, 0.01, 0.1}
	features := export.FeatureStatsDiskOperationDuration
	fetcher, err := ebpf.NewStatsFetcher(&config.EBPFTracer{}, &features, &attributes.SelectorConfig{}, bounds)
	require.NoError(t, err)
	t.Cleanup(func() { fetcher.Close() })
	require.NotNil(t, fetcher.DiskIOAccumMap(), "the disk probes must be attached on this kernel")

	loopDev := attachLoopDevice(t)
	reader := newDiskReader(ebpfDiskAccum{accum: fetcher.DiskIOAccumMap()}, bounds,
		fetcher.DiskStatusIsBlkStatus(), &deviceNames{sysRoot: "/sys"})
	reader.readStats() // forget the I/O that happened before this test

	f, err := os.OpenFile(loopDev, os.O_RDWR|unix.O_DIRECT, 0)
	require.NoError(t, err)
	defer f.Close()
	block := alignedBuffer(t, directIOBlockSize)
	for i := range directIOBlocks {
		_, err := f.WriteAt(block, int64(i*directIOBlockSize))
		require.NoError(t, err)
	}
	for i := range directIOBlocks {
		_, err := f.ReadAt(block, int64(i*directIOBlockSize))
		require.NoError(t, err)
	}

	deviceName := filepath.Base(loopDev)
	completed := map[ebpf.DiskIODirectionCode]uint64{}
	for _, stat := range reader.readStats() {
		if stat.DiskIO.Device != deviceName {
			continue
		}
		assert.Empty(t, stat.DiskIO.ErrorType)
		for _, latency := range stat.DiskIO.Latency {
			assert.Positive(t, latency.Seconds)
			completed[stat.DiskIO.Direction] += latency.Count
		}
	}
	assert.Equal(t, map[ebpf.DiskIODirectionCode]uint64{
		ebpf.CodeDiskDirectionWrite: directIOBlocks,
		ebpf.CodeDiskDirectionRead:  directIOBlocks,
	}, completed)
}

// attachLoopDevice attaches a new loop device to a sparse file and returns its /dev path
func attachLoopDevice(t *testing.T) string {
	t.Helper()
	backing, err := os.Create(filepath.Join(t.TempDir(), "disk.img"))
	require.NoError(t, err)
	t.Cleanup(func() { backing.Close() })
	require.NoError(t, backing.Truncate(loopBackingFileSize))

	control, err := os.OpenFile("/dev/loop-control", os.O_RDWR, 0)
	require.NoError(t, err)
	defer control.Close()
	index, err := unix.IoctlRetInt(int(control.Fd()), unix.LOOP_CTL_GET_FREE)
	require.NoError(t, err)

	path := fmt.Sprintf("/dev/loop%d", index)
	loop, err := os.OpenFile(path, os.O_RDWR, 0)
	require.NoError(t, err)
	require.NoError(t, unix.IoctlSetInt(int(loop.Fd()), unix.LOOP_SET_FD, int(backing.Fd())))
	t.Cleanup(func() {
		_ = unix.IoctlSetInt(int(loop.Fd()), unix.LOOP_CLR_FD, 0)
		loop.Close()
	})
	return path
}

// alignedBuffer returns a page-aligned buffer, as O_DIRECT requires
func alignedBuffer(t *testing.T, size int) []byte {
	t.Helper()
	buf, err := unix.Mmap(-1, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	require.NoError(t, err)
	t.Cleanup(func() { _ = unix.Munmap(buf) })
	return buf
}
