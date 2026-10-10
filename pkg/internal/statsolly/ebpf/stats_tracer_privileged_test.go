// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package ebpf

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
)

// Without the kernel's REQ_OP_ZONE_APPEND, the probes would not measure zone appends
func TestKernelBlockTracepointLayoutZoneAppendOp(t *testing.T) {
	layout, err := kernelBlockTracepointLayout(slog.Default())
	require.NoError(t, err)
	assert.NotZero(t, layout.zoneAppendOp, "every supported kernel has REQ_OP_ZONE_APPEND")
}

// mapSizes returns the size of each loaded map, as the kernel reports it
func mapSizes(t *testing.T, maps *StatsMaps) map[string]uint32 {
	t.Helper()
	sizes := map[string]uint32{}
	fields := reflect.ValueOf(*maps)
	for i := range fields.NumField() {
		info, err := fields.Field(i).Interface().(*ebpf.Map).Info()
		require.NoError(t, err)
		sizes[fields.Type().Field(i).Tag.Get("ebpf")] = info.MaxEntries
	}
	return sizes
}

// The maps of the storage features that are off take a single entry of kernel memory, and the
// other maps keep their sizes
func TestStorageMapsOfDisabledFeatures(t *testing.T) {
	spec, err := LoadStats()
	require.NoError(t, err)
	cpus, err := ebpf.PossibleCPU()
	require.NoError(t, err)
	sizeInFlightMaps(spec, cpus)
	load := func(features export.Features, selection *attributes.SelectorConfig) map[string]uint32 {
		fetcher, err := NewStatsFetcher(&config.EBPFTracer{}, &features, attributes.UndefinedGroup, selection, ProbeReads{})
		require.NoError(t, err)
		t.Cleanup(func() {
			fetcher.Close()
			fetcher.objects.Close()
		})
		if features.StatsDisk() {
			require.NotNil(t, fetcher.DiskIOAccumMap(), "the disk probes must be attached on this kernel")
		}
		if features.StatsFsSync() && fetcher.FsSyncAccumMap() == nil {
			t.Skipf("the file sync probes can't be attached on this kernel: %v", fetcher.DisabledStorageFeatures())
		}
		sizes := mapSizes(t, &fetcher.objects.StatsMaps)
		for name, m := range spec.Maps {
			// the loader aligns the size of a ring buffer to the page size, 64 KiB on some arm64
			// kernels, and no ring buffer is a storage map
			if m.Type == ebpf.RingBuf {
				delete(sizes, name)
			}
		}
		return sizes
	}

	for name, entries := range load(export.FeatureStatsTCPRetransmits, &attributes.SelectorConfig{}) {
		want := spec.Maps[name].MaxEntries
		if isStorageMap(name) {
			want = 1
		}
		assert.Equal(t, want, entries, "TCP only: %s", name)
	}

	for name, entries := range load(export.FeatureStatsDisk, &attributes.SelectorConfig{}) {
		want := spec.Maps[name].MaxEntries
		if slices.Contains(cgroupNameMaps, name) || strings.HasPrefix(name, "fs_sync_") || strings.HasPrefix(name, "nfs_") {
			want = 1
		}
		assert.Equal(t, want, entries, "disk without the cgroups: %s", name)
	}

	withContainers := &attributes.SelectorConfig{SelectionCfg: attributes.Selection{
		attributes.StatDiskOperations.Section: attributes.InclusionLists{Include: []string{"container.id"}},
	}}
	for name, entries := range load(export.FeatureStatsDisk, withContainers) {
		want := spec.Maps[name].MaxEntries
		if strings.HasPrefix(name, "fs_sync_") || strings.HasPrefix(name, "nfs_") {
			want = 1
		}
		assert.Equal(t, want, entries, "disk: %s", name)
	}

	for name, entries := range load(export.FeatureStatsFsSync, &attributes.SelectorConfig{}) {
		want := spec.Maps[name].MaxEntries
		if isStorageMap(name) && !strings.HasPrefix(name, "fs_sync_") {
			want = 1
		}
		assert.Equal(t, want, entries, "file syncs without the cgroups: %s", name)
	}
}

// When the storage programs can't be loaded, the stats are loaded again without them: that load
// creates the storage maps again, with a single entry
func TestStatsLoadWithoutStorageAfterAFailedLoad(t *testing.T) {
	layout, err := kernelBlockTracepointLayout(slog.Default())
	require.NoError(t, err)
	storage := storageProbes{layout: layout, disk: true}

	var objects StatsObjects
	load := newStatsLoader(&objects, 0, nil, nil)
	loads := 0
	err = storage.loadOrDisable(func(toDisable []string) error {
		loads++
		if err := load(toDisable); err != nil || loads > 1 {
			return err
		}
		// fail once the disk maps exist with their full size, as a verifier error would
		assert.Equal(t, uint32(1<<12), mapSizes(t, &objects.StatsMaps)["disk_io_accum"])
		require.NoError(t, objects.Close())
		return errors.New("injected load failure")
	}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { objects.Close() })

	assert.Equal(t, 2, loads)
	assert.Equal(t, uint32(1), mapSizes(t, &objects.StatsMaps)["disk_io_accum"])
}

// attachPlannedFsSyncProbes loads and attaches the file sync probes as OBI plans them for this
// kernel. It skips the test where the kernel can't load or attach them.
func attachPlannedFsSyncProbes(t *testing.T) storageProbes {
	t.Helper()
	features := export.FeatureStatsFsSyncDuration
	storage := planStorageProbes(slog.Default(), &features)
	var objects StatsObjects
	load := newStatsLoader(&objects, 0, nil, map[string]any{
		"fs_sync_latency_bounds_ns": latencyBoundsNs(export.FsSyncLatencyBounds),
	})
	require.NoError(t, storage.loadOrDisable(load, nil))
	t.Cleanup(func() { objects.Close() })
	if !storage.fsSync {
		t.Skipf("the file sync probes can't be loaded on this kernel: %v", storage.disabled)
	}
	links, err := storage.attach(slog.Default(), &objects)
	if err != nil {
		t.Skipf("the file sync probes can't be attached on this kernel: %v", err)
	}
	t.Cleanup(func() { closeAll(links) })
	return storage
}

// The file sync hooks are timed with fentry and fexit programs where the kernel's trampolines are
// safe for the functions that sleep and the kernel BTF has their function, else with kprobes
func TestFsSyncMechanisms(t *testing.T) {
	storage := attachPlannedFsSyncProbes(t)
	kernel, err := btf.LoadKernelSpec()
	require.NoError(t, err)
	safe := hasStruct(kernel, safeTrampolineStruct)

	for _, hook := range fsSyncHooks {
		mechanism := storage.fsSyncMechanisms[hook.function]
		switch {
		case safe && hasFunc(kernel, hook.kernelFunction()):
			assert.Equal(t, fsSyncMechanismTracing, mechanism, hook.function)
		case hook.function == fsSyncRequiredHook:
			assert.Equal(t, fsSyncMechanismKprobes, mechanism, hook.function)
		default:
			assert.NotEqual(t, fsSyncMechanismTracing, mechanism, hook.function)
		}
	}
	assert.NotEqual(t, fsSyncMechanismNone, storage.fsSyncMechanisms["ksys_sync"], "sync(2) is timed on every kernel")
	assert.NotEqual(t, fsSyncMechanismNone, storage.fsSyncMechanisms["sys_fsync"], "fsync(2) is timed on every kernel")
}

// fsyncsOf counts the successful fsyncs that the kernel accumulated
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

// The kprobes, which time the hooks that the fentry and fexit programs can't, time the syncs too
func TestFsSyncKprobes(t *testing.T) {
	if _, err := os.Stat("/sys/bus/event_source/devices/kprobe/type"); err != nil {
		t.Skip("the kernel doesn't support kprobes")
	}
	storage := storageProbes{fsSync: true}
	var objects StatsObjects
	load := newStatsLoader(&objects, 0, nil, map[string]any{
		"fs_sync_latency_bounds_ns": latencyBoundsNs(export.FsSyncLatencyBounds),
	})
	require.NoError(t, storage.loadOrDisable(load, nil))
	t.Cleanup(func() { objects.Close() })
	links, err := storage.attach(slog.Default(), &objects)
	require.NoError(t, err)
	t.Cleanup(func() { closeAll(links) })
	for function, mechanism := range storage.fsSyncMechanisms {
		assert.NotEqual(t, fsSyncMechanismTracing, mechanism, function)
	}
	assert.Equal(t, fsSyncMechanismKprobes, storage.fsSyncMechanisms[fsSyncRequiredHook])

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
