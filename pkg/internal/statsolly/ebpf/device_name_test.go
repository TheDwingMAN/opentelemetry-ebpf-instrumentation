// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeviceName(t *testing.T) {
	dir := t.TempDir()
	// A real /sys/dev/block/<major>:<minor> is a symlink into the device tree
	// whose basename is the device node name.
	require.NoError(t, os.Symlink("../../devices/pci0000:00/block/sdb", filepath.Join(dir, "8:16")))
	withSysBlockDir(t, dir)

	// dev_t for major 8, minor 16 is (8<<20)|16 == 0x800010.
	assert.Equal(t, "sdb", deviceName(0x800010))
	// Cached lookups return the same resolved name.
	assert.Equal(t, "sdb", deviceName(0x800010))
	// An unresolvable device falls back to "<major>:<minor>".
	assert.Equal(t, "9:0", deviceName(9<<20))
}

// withSysBlockDir points the resolver at a fixture directory and clears the
// name cache for the duration of a test.
func withSysBlockDir(t *testing.T, dir string) {
	t.Helper()
	old := sysBlockDir
	sysBlockDir = dir
	resetDevNameCache()
	t.Cleanup(func() {
		sysBlockDir = old
		resetDevNameCache()
	})
}

func resetDevNameCache() {
	devNameMu.Lock()
	devNameCache = map[uint32]string{}
	devNameMu.Unlock()
}
