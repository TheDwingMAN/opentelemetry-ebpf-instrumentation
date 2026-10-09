// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package ebpf

import (
	"errors"
	"log/slog"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
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
	load := func(features export.Features) map[string]uint32 {
		fetcher, err := NewStatsFetcher(&config.EBPFTracer{}, &features, attributes.UndefinedGroup,
			&attributes.SelectorConfig{}, LatencyHistograms{}, ProbeReads{})
		require.NoError(t, err)
		t.Cleanup(func() {
			fetcher.Close()
			fetcher.objects.Close()
		})
		if features.StatsDisk() {
			require.NotNil(t, fetcher.DiskIOAccumMap(), "the disk probes must be attached on this kernel")
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

	for name, entries := range load(export.FeatureStatsTCPRetransmits) {
		want := spec.Maps[name].MaxEntries
		if isStorageMap(name) {
			want = 1
		}
		assert.Equal(t, want, entries, "TCP only: %s", name)
	}

	for name, entries := range load(export.FeatureStatsDiskOperationDuration) {
		want := spec.Maps[name].MaxEntries
		switch name {
		case "disk_bio_accum", "disk_bio_devices", "disk_bio_start", "fs_sync_accum", "fs_sync_start",
			"nfs_io_accum", "nfs_procedure_accum", "nfs_task_cgroup":
			want = 1
		}
		assert.Equal(t, want, entries, "disk: %s", name)
	}
}

// When the storage programs can't be loaded, the stats are loaded again without them: that load
// creates the storage maps again, with a single entry
func TestStatsLoadWithoutStorageAfterAFailedLoad(t *testing.T) {
	layout, err := kernelBlockTracepointLayout(slog.Default())
	require.NoError(t, err)
	storage := storageProbes{layout: layout, disk: true}

	var objects StatsObjects
	load := newStatsLoader(&objects, 0, nil)
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
