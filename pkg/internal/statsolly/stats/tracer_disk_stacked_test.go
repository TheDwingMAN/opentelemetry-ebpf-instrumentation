// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeBlockDevice creates the sysfs directory of a block device under /block, with its dev file
// and the given subdirectories and slaves
func fakeBlockDevice(t *testing.T, root, name, numbers string, subdirs []string, slaves ...string) {
	t.Helper()
	dir := filepath.Join(root, "block", name)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "slaves"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dev"), []byte(numbers+"\n"), 0o644))
	for _, sub := range subdirs {
		require.NoError(t, os.MkdirAll(filepath.Join(dir, sub), 0o755))
	}
	for _, slave := range slaves {
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "slaves", slave), 0o755))
	}
	// /dev/block/<maj:min> links to the device directory
	require.NoError(t, os.MkdirAll(filepath.Join(root, "dev", "block"), 0o755))
	require.NoError(t, os.Symlink(dir, filepath.Join(root, "dev", "block", numbers)))
}

func fakeHostDevices(t *testing.T) string {
	root := t.TempDir()
	fakeBlockDevice(t, root, "nvme0n1", "259:0", []string{"mq"})
	fakeBlockDevice(t, root, "loop0", "7:0", []string{"mq", "loop"})
	fakeBlockDevice(t, root, "dm-0", "252:0", []string{"dm"}, "nvme0n1p2")        // LVM
	fakeBlockDevice(t, root, "dm-1", "252:1", []string{"dm", "mq"}, "sdb", "sdc") // multipath
	fakeBlockDevice(t, root, "md0", "9:0", []string{"md"}, "sdd", "sde")          // RAID
	fakeBlockDevice(t, root, "sdb", "8:16", []string{"mq"})
	return root
}

func TestStackedDevices(t *testing.T) {
	root := fakeHostDevices(t)
	names := &deviceNames{sysRoot: root, procRoot: root}
	assert.False(t, names.stacked(259, 0), "a disk")
	assert.False(t, names.stacked(8, 16), "a path of a multipath device")
	assert.True(t, names.stacked(7, 0), "a loop device")
	assert.True(t, names.stacked(252, 0), "an LVM volume")
	assert.True(t, names.stacked(252, 1), "a multipath device")
	assert.True(t, names.stacked(9, 0), "an md RAID volume")
	assert.False(t, names.stacked(8, 99), "an unknown device")
}
