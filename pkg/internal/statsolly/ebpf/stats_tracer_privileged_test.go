// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package ebpf

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export"
	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
)

// After a storage probe fails to attach, the probes are loaded again without its feature: its map
// takes a single entry of kernel memory, and the agent doesn't read it
func TestStorageFeatureDisabledAfterAnAttachFailure(t *testing.T) {
	require.NoError(t, rlimit.RemoveMemlock())
	features := export.FeatureStatsDiskServiceDuration
	loads := 0
	fetcher, err := loadDegradingStorage(slog.Default(), planStorage(slog.Default(), &features),
		func(storage storagePlan) (*StatsFetcher, error) {
			loads++
			fetcher, err := loadAndAttach(&config.EBPFTracer{}, &features, nil, false, storage, CgroupReads{})
			if err != nil || loads > 1 {
				return fetcher, err
			}
			require.NotNil(t, fetcher.DiskIOAccumMap(), "the disk probes attach on this kernel")
			assert.Equal(t, uint32(1<<12), fetcher.objects.DiskIoAccum.MaxEntries())
			fetcher.Close()
			fetcher.objects.Close()
			return nil, &storageError{features: export.FeatureStatsDisk, err: errors.New("injected attach failure")}
		})
	require.NoError(t, err)
	t.Cleanup(func() {
		fetcher.Close()
		fetcher.objects.Close()
	})

	assert.Equal(t, 2, loads)
	assert.Nil(t, fetcher.DiskIOAccumMap())
	assert.Equal(t, uint32(1), fetcher.objects.DiskIoAccum.MaxEntries())
}

// loadFsSyncPrograms loads the stats programs with the file sync kprobes, and the fentry and fexit
// programs of the hooks in tracing
func loadFsSyncPrograms(t *testing.T, tracing map[string]bool) *StatsObjects {
	t.Helper()
	require.NoError(t, rlimit.RemoveMemlock())
	spec, err := LoadStats()
	require.NoError(t, err)
	setFsSyncTracingTargets(spec)
	require.NoError(t, fixupSpec(spec, fsSyncProgramsToDisable(true, tracing)))
	var objects StatsObjects
	err = ebpfconvenience.LoadSpec(spec, &objects, nil, map[string]*ebpf.Map{}, &sync.Mutex{}, "", nil)
	if errors.Is(err, unix.EPERM) {
		t.Skipf("this kernel doesn't let the stats programs load: %v", err)
	}
	require.NoError(t, err)
	t.Cleanup(func() { objects.Close() })
	return &objects
}

// The file sync hooks are timed with fentry and fexit programs where the kernel's trampolines are
// safe for the functions that sleep and its BTF has their function, else with kprobes
func TestFsSyncMechanisms(t *testing.T) {
	kernel, err := btf.LoadKernelSpec()
	require.NoError(t, err)
	tracing := fsSyncTracingHooks(kernel)
	links, mechanisms, err := attachFsSync(slog.Default(), loadFsSyncPrograms(t, tracing), tracing)
	require.NoError(t, err)
	t.Cleanup(func() { closeAll(links) })
	logFsSyncMechanisms(slog.Default(), mechanisms)

	for _, hook := range fsSyncHooks {
		switch {
		case tracing[hook.function]:
			assert.Equal(t, fsSyncMechanismTracing, mechanisms[hook.function], hook.function)
		case hook.function == fsSyncRequiredHook:
			assert.Equal(t, fsSyncMechanismKprobes, mechanisms[hook.function], hook.function)
		default:
			assert.NotEqual(t, fsSyncMechanismTracing, mechanisms[hook.function], hook.function)
		}
	}
	assert.NotEqual(t, fsSyncMechanismNone, mechanisms["ksys_sync"], "sync(2) is timed on every kernel")
	assert.NotEqual(t, fsSyncMechanismNone, mechanisms["sys_fsync"], "fsync(2) is timed on every kernel")
}

// The kprobes, which time the hooks that the fentry and fexit programs can't, time the syncs too
func TestFsSyncKprobes(t *testing.T) {
	if _, err := os.Stat("/sys/bus/event_source/devices/kprobe/type"); err != nil {
		t.Skip("the kernel doesn't support kprobes")
	}
	objects := loadFsSyncPrograms(t, nil)
	links, mechanisms, err := attachFsSync(slog.Default(), objects, nil)
	require.NoError(t, err)
	t.Cleanup(func() { closeAll(links) })
	for function, mechanism := range mechanisms {
		assert.NotEqual(t, fsSyncMechanismTracing, mechanism, function)
	}
	assert.Equal(t, fsSyncMechanismKprobes, mechanisms[fsSyncRequiredHook])

	const syncs = 5
	before := fsyncsOf(t, objects.FsSyncAccum)
	f, err := os.Create(filepath.Join(t.TempDir(), "synced"))
	require.NoError(t, err)
	defer f.Close()
	for range syncs {
		_, err := f.WriteString("synced")
		require.NoError(t, err)
		require.NoError(t, f.Sync())
	}
	assert.GreaterOrEqual(t, fsyncsOf(t, objects.FsSyncAccum)-before, uint64(syncs), "other processes may sync files too")
}

// fsyncsOf counts the successful fsyncs of the accumulation map
func fsyncsOf(t *testing.T, accum *ebpf.Map) uint64 {
	t.Helper()
	var key StatsFsSyncKeyT
	var value StatsFsSyncAccumT
	var fsyncs uint64
	entries := accum.Iterate()
	for entries.Next(&key, &value) {
		if key.Type == StatsFsSyncTypeFsSyncTypeFsync && key.Status == 0 {
			for _, count := range value.LatencyCount {
				fsyncs += count
			}
		}
	}
	require.NoError(t, entries.Err())
	return fsyncs
}
