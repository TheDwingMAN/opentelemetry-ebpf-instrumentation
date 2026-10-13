// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package ebpf

import (
	"errors"
	"log/slog"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export"
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
			fetcher, err := loadAndAttach(&config.EBPFTracer{}, &features, nil, false, storage, false)
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
