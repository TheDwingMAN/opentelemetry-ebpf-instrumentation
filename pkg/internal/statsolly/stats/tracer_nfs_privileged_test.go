// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package stats

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

// The disk stats load whether or not the kernel has the NFS client or its BTF
func TestNFSStatsAreOptional(t *testing.T) {
	features := export.FeatureStatsNFS | export.FeatureStatsDiskOperations
	fetcher, err := ebpf.NewStatsFetcher(&config.EBPFTracer{}, &features, attributes.UndefinedGroup, allAttributes, ebpf.ProbeReads{})
	require.NoError(t, err)
	t.Cleanup(func() { fetcher.Close() })

	assert.NotNil(t, fetcher.DiskIOAccumMap())
	t.Logf("storage features not measured: %v", fetcher.DisabledStorageFeatures())
}

func TestNFSProbesAttachWhenTheirModulesAreLoaded(t *testing.T) {
	if _, err := os.Stat("/sys/module/sunrpc"); err == nil {
		t.Skip("the sunrpc module is already loaded")
	}
	if err := exec.Command("modprobe", "--dry-run", "nfs").Run(); err != nil {
		t.Skipf("the nfs module can't be loaded: %v", err)
	}

	features := export.FeatureStatsNFS
	fetcher, err := ebpf.NewStatsFetcher(&config.EBPFTracer{}, &features, attributes.UndefinedGroup, allAttributes, ebpf.ProbeReads{})
	require.NoError(t, err)
	t.Cleanup(func() { fetcher.Close() })

	disabled := fetcher.DisabledStorageFeatures()
	require.Len(t, disabled, 2, "both NFS client metrics wait for their modules: %v", disabled)
	for _, d := range disabled {
		if strings.Contains(d.Reason, "doesn't describe the") || strings.Contains(d.Reason, "can't tell the arguments of") {
			t.Skipf("the kernel can't load the NFS client probes before their modules: %s", d.Reason)
		}
		require.Contains(t, d.Reason, "waiting for the tracepoints", d.Feature)
	}
	assert.NotNil(t, fetcher.NFSProcedureAccumMap())
	assert.NotNil(t, fetcher.NFSIOAccumMap())

	out, err := exec.Command("modprobe", "nfs").CombinedOutput()
	require.NoError(t, err, string(out))
	fetcher.RefreshNFSProbes()
	assert.Empty(t, fetcher.DisabledStorageFeatures())
}
