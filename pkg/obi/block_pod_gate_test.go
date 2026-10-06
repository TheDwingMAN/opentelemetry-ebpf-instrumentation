// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package obi

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export"
)

// cgroupRoot writes a cgroup hierarchy root: v2 has cgroup.controllers and
// the controllers enabled for the children in cgroup.subtree_control; v1
// (a tmpfs of per-controller hierarchies) has neither.
func cgroupRoot(t *testing.T, v2 bool, subtree string) string {
	t.Helper()
	root := t.TempDir()
	if !v2 {
		require.NoError(t, os.Mkdir(filepath.Join(root, "blkio"), 0o755))
		return root
	}
	require.NoError(t, os.WriteFile(filepath.Join(root, "cgroup.controllers"),
		[]byte("cpuset cpu io memory hugetlb pids rdma misc\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "cgroup.subtree_control"), []byte(subtree), 0o644))
	return root
}

func TestBlockPodUnsupported(t *testing.T) {
	// The S0-d lab: cgroup v2, io delegated from the root down to the
	// container leaves.
	host := cgroupRoot(t, true, "cpuset cpu io memory hugetlb pids rdma misc\n")
	assert.Empty(t, blockPodUnsupported([]string{host}))

	assert.Contains(t, blockPodUnsupported([]string{cgroupRoot(t, false, "")}), "cgroup v2",
		"cgroup v1: blkcg ids never equal the pod cgroups' ids")
	assert.Contains(t, blockPodUnsupported([]string{cgroupRoot(t, true, "cpu memory pids\n")}), "io controller",
		"io not delegated: every request is charged to the root")
	assert.Contains(t, blockPodUnsupported([]string{filepath.Join(t.TempDir(), "missing")}), "cgroup v2")

	// OBI in a cgroup namespace sees its own leaf as /sys/fs/cgroup, whose
	// subtree_control is empty; the host's root is read through PID 1.
	container := cgroupRoot(t, true, "")
	assert.Empty(t, blockPodUnsupported([]string{container, host}))
	assert.Empty(t, blockPodUnsupported([]string{cgroupRoot(t, false, ""), host}),
		"a hybrid or v1 view of OBI's own /sys does not hide the host's v2 root")
}

func TestConfigValidate_BlockPodNeedsCgroupV2IO(t *testing.T) {
	validate := func(t *testing.T, features string, unsupported func() string) (*Config, string) {
		t.Helper()
		var logs bytes.Buffer
		restore := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
		t.Cleanup(func() { slog.SetDefault(restore) })

		cfg := loadConfig(t, envMap{
			"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "localhost:1234",
			"OTEL_EBPF_EXECUTABLE_PATH":           "foo",
			"OTEL_EBPF_METRICS_FEATURES":          features,
		})
		require.NoError(t, cfg.validate(validationContext{checkBlockPod: unsupported}))
		return cfg, logs.String()
	}
	supported := func() string { return "" }
	unsupported := func() string { return "no cgroup v2 here" }

	t.Run("supported", func(t *testing.T) {
		cfg, logs := validate(t, "storage_block,storage_block_pod", supported)
		assert.True(t, cfg.Metrics.Features.StorageBlockPod())
		assert.NotContains(t, logs, "storage_block_pod")
	})
	t.Run("unsupported: off with one warning", func(t *testing.T) {
		cfg, logs := validate(t, "storage_block,storage_block_pod", unsupported)
		assert.False(t, cfg.Metrics.Features.StorageBlockPod())
		assert.True(t, cfg.Metrics.Features.StorageBlockIo(), "the other block metrics stay")
		assert.Contains(t, logs, "feature=storage_block_pod")
		assert.Contains(t, logs, "no cgroup v2 here")
		assert.Equal(t, 1, bytes.Count([]byte(logs), []byte("feature=storage_block_pod")))
	})
	t.Run("not asked for: the host is not checked", func(t *testing.T) {
		cfg, _ := validate(t, "storage_block", func() string {
			t.Fatal("the cgroup hierarchy is read only when storage_block_pod is on")
			return ""
		})
		assert.Equal(t, export.FeatureStorageBlock, cfg.Metrics.Features&^export.FeatureApplicationRED&^export.FeatureApplicationSizes)
	})
	t.Run("static validation reads no host state", func(t *testing.T) {
		cfg, _ := validate(t, "storage_block_pod", nil)
		assert.True(t, cfg.Metrics.Features.StorageBlockPod())
	})
}
