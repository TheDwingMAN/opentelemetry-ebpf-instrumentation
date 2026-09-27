// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package stats

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
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

	// environment of the child processes of TestDiskIOIsChargedPerCgroup
	envWriterDevice = "OBI_TEST_DISK_WRITER_DEVICE"
	envWriterBlocks = "OBI_TEST_DISK_WRITER_BLOCKS"
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
		fetcher.DiskStatusIsBlkStatus(), &deviceNames{sysRoot: "/sys"},
		newCgroupContainers(ebpfCgroupNames{names: fetcher.DiskCgroupNamesMap()}))
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
	operations := map[ebpf.DiskIODirectionCode]uint64{}
	transferred := map[ebpf.DiskIODirectionCode]uint64{}
	for _, stat := range reader.readStats() {
		if stat.DiskIO.Device != deviceName {
			continue
		}
		assert.Empty(t, stat.DiskIO.ErrorType)
		for _, latency := range stat.DiskIO.Latency {
			assert.Positive(t, latency.Seconds)
			completed[stat.DiskIO.Direction] += latency.Count
		}
		operations[stat.DiskIO.Direction] += stat.DiskIO.Operations
		transferred[stat.DiskIO.Direction] += stat.DiskIO.Bytes
	}
	perDirection := func(value uint64) map[ebpf.DiskIODirectionCode]uint64 {
		return map[ebpf.DiskIODirectionCode]uint64{
			ebpf.CodeDiskDirectionWrite: value,
			ebpf.CodeDiskDirectionRead:  value,
		}
	}
	assert.Equal(t, perDirection(directIOBlocks), completed)
	assert.Equal(t, perDirection(directIOBlocks), operations)
	assert.Equal(t, perDirection(directIOBlocks*directIOBlockSize), transferred)
}

// TestDiskIOIsChargedPerCgroup writes to the same loop device from two processes in two
// container-like cgroups, and checks that each container is charged exactly its own I/O.
func TestDiskIOIsChargedPerCgroup(t *testing.T) {
	cgroupRoot := ioCgroupRoot(t)
	// a counter alone must load the disk probes, without the histogram
	features := export.FeatureStatsDiskOperations
	bounds := []float64{0.001}
	fetcher, err := ebpf.NewStatsFetcher(&config.EBPFTracer{}, &features, &attributes.SelectorConfig{}, bounds)
	require.NoError(t, err)
	t.Cleanup(func() { fetcher.Close() })

	loopDev := attachLoopDevice(t)
	reader := newDiskReader(ebpfDiskAccum{accum: fetcher.DiskIOAccumMap()}, bounds,
		fetcher.DiskStatusIsBlkStatus(), &deviceNames{sysRoot: "/sys"},
		newCgroupContainers(ebpfCgroupNames{names: fetcher.DiskCgroupNamesMap()}))
	reader.readStats() // forget the I/O that happened before this test

	writers := map[string]uint64{
		strings.Repeat("a1", 32): 64,
		strings.Repeat("b2", 32): 32,
	}
	for containerID, blocks := range writers {
		cgroup := filepath.Join(cgroupRoot, "docker-"+containerID+".scope")
		runWriterInCgroup(t, cgroup, loopDev, blocks)
	}

	deviceName := filepath.Base(loopDev)
	charged := map[string]uint64{}
	for _, stat := range reader.readStats() {
		if stat.DiskIO.Device == deviceName && stat.DiskIO.Direction == ebpf.CodeDiskDirectionWrite {
			charged[stat.DiskIO.ContainerID] += stat.DiskIO.Operations
		}
	}
	assert.Equal(t, writers, charged)
}

// TestDiskIOWriterProcess is not a test: TestDiskIOIsChargedPerCgroup runs it as a child process
// that writes blocks to a device once its parent has moved it to a cgroup and tells it to start.
func TestDiskIOWriterProcess(t *testing.T) {
	device := os.Getenv(envWriterDevice)
	if device == "" {
		t.Skip("only runs as a child process of TestDiskIOIsChargedPerCgroup")
	}
	blocks, err := strconv.Atoi(os.Getenv(envWriterBlocks))
	require.NoError(t, err)
	_, err = bufio.NewReader(os.Stdin).ReadString('\n')
	require.NoError(t, err)

	f, err := os.OpenFile(device, os.O_WRONLY|unix.O_DIRECT, 0)
	require.NoError(t, err)
	defer f.Close()
	block := alignedBuffer(t, directIOBlockSize)
	for i := range blocks {
		_, err := f.WriteAt(block, int64(i*directIOBlockSize))
		require.NoError(t, err)
	}
}

// ioCgroupRoot returns the root of the cgroup hierarchy of the io (v2) or blkio (v1)
// controller, where the test can create cgroups
func ioCgroupRoot(t *testing.T) string {
	t.Helper()
	if controllers, err := os.ReadFile("/sys/fs/cgroup/cgroup.controllers"); err == nil {
		if !strings.Contains(string(controllers), "io") {
			t.Skip("the cgroup v2 io controller is not available")
		}
		require.NoError(t, os.WriteFile("/sys/fs/cgroup/cgroup.subtree_control", []byte("+io"), 0o644))
		return "/sys/fs/cgroup"
	}
	if _, err := os.Stat("/sys/fs/cgroup/blkio/cgroup.procs"); err == nil {
		return "/sys/fs/cgroup/blkio"
	}
	t.Skip("no io or blkio cgroup controller")
	return ""
}

// runWriterInCgroup runs TestDiskIOWriterProcess in a new cgroup, writing blocks to the device
func runWriterInCgroup(t *testing.T, cgroup, device string, blocks uint64) {
	t.Helper()
	require.NoError(t, os.Mkdir(cgroup, 0o755))
	t.Cleanup(func() { _ = os.Remove(cgroup) })

	cmd := exec.Command(os.Args[0], "-test.run=^TestDiskIOWriterProcess$")
	cmd.Env = append(os.Environ(), envWriterDevice+"="+device, envWriterBlocks+"="+strconv.FormatUint(blocks, 10))
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	start, err := cmd.StdinPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())

	require.NoError(t, os.WriteFile(filepath.Join(cgroup, "cgroup.procs"), []byte(strconv.Itoa(cmd.Process.Pid)), 0o644))
	_, err = start.Write([]byte("start\n"))
	require.NoError(t, err)
	require.NoError(t, cmd.Wait())
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
