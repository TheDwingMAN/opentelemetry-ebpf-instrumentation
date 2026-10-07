// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"testing"

	"github.com/prometheus/procfs"
	"github.com/stretchr/testify/assert"
)

func mountInfo(fsType, mountPoint, majorMinor, source string) *procfs.MountInfo {
	return &procfs.MountInfo{
		FSType:        fsType,
		MountPoint:    mountPoint,
		MajorMinorVer: majorMinor,
		Source:        source,
	}
}

func TestLocalPVDevs(t *testing.T) {
	tests := []struct {
		name   string
		mounts []*procfs.MountInfo
		want   map[uint32]FsTypeCode
	}{
		{
			name: "ext4 kubelet volume mount is included",
			mounts: []*procfs.MountInfo{
				mountInfo("ext4",
					"/var/lib/kubelet/pods/55293f39-c745-4578-accb-f3e5cfc7b303/volumes/kubernetes.io~local-volume/pv-1",
					"8:16", "/dev/sdb1"),
			},
			want: map[uint32]FsTypeCode{8<<devMinorBits | 16: CodeFsExt4},
		},
		{
			name: "xfs CSI mount with trailing /mount segment is included",
			mounts: []*procfs.MountInfo{
				mountInfo("xfs",
					"/var/lib/kubelet/pods/11111111-2222-3333-4444-555555555555/volumes/kubernetes.io~csi/pvc-abc/mount",
					"259:3", "/dev/nvme0n1"),
			},
			want: map[uint32]FsTypeCode{259<<devMinorBits | 3: CodeFsXFS},
		},
		{
			name: "btrfs kubelet volume mount, including its anonymous major 0, is included",
			mounts: []*procfs.MountInfo{
				mountInfo("btrfs",
					"/var/lib/kubelet/pods/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/volumes/kubernetes.io~csi/pvc-btrfs/mount",
					"0:42", "/dev/whatever"),
			},
			want: map[uint32]FsTypeCode{42: CodeFsBtrfs},
		},
		{
			name: "ext4 mount outside the kubelet volume path is excluded",
			mounts: []*procfs.MountInfo{
				mountInfo("ext4", "/", "8:1", "/dev/sda1"),
			},
			want: map[uint32]FsTypeCode{},
		},
		{
			name: "nfs kubelet volume mount is excluded: network filesystems are never filtered",
			mounts: []*procfs.MountInfo{
				mountInfo("nfs4",
					"/var/lib/kubelet/pods/55293f39-c745-4578-accb-f3e5cfc7b303/volumes/kubernetes.io~nfs/pvc-nfs",
					"0:574", "10.0.0.1:/export"),
			},
			want: map[uint32]FsTypeCode{},
		},
		{
			name: "malformed MajorMinorVer is skipped rather than panicking",
			mounts: []*procfs.MountInfo{
				mountInfo("ext4",
					"/var/lib/kubelet/pods/55293f39-c745-4578-accb-f3e5cfc7b303/volumes/kubernetes.io~local-volume/pv-bad",
					"not-a-number", "/dev/sdb1"),
			},
			want: map[uint32]FsTypeCode{},
		},
		{
			name: "multiple local-filesystem PV mounts are all included",
			mounts: []*procfs.MountInfo{
				mountInfo("ext4",
					"/var/lib/kubelet/pods/55293f39-c745-4578-accb-f3e5cfc7b303/volumes/kubernetes.io~local-volume/pv-1",
					"8:16", "/dev/sdb1"),
				mountInfo("xfs",
					"/var/lib/kubelet/pods/11111111-2222-3333-4444-555555555555/volumes/kubernetes.io~csi/pvc-abc/mount",
					"259:3", "/dev/nvme0n1"),
			},
			want: map[uint32]FsTypeCode{8<<devMinorBits | 16: CodeFsExt4, 259<<devMinorBits | 3: CodeFsXFS},
		},
		{
			name:   "no mounts yields an empty set",
			mounts: nil,
			want:   map[uint32]FsTypeCode{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, localPVDevs(tc.mounts))
		})
	}
}

func TestParseDevT(t *testing.T) {
	tests := []struct {
		name       string
		majorMinor string
		want       uint32
		wantOK     bool
	}{
		{name: "typical device", majorMinor: "259:3", want: 259<<devMinorBits | 3, wantOK: true},
		{name: "anonymous major 0", majorMinor: "0:42", want: 42, wantOK: true},
		{name: "missing colon", majorMinor: "2593", wantOK: false},
		{name: "non-numeric major", majorMinor: "x:3", wantOK: false},
		{name: "non-numeric minor", majorMinor: "259:y", wantOK: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseDevT(tc.majorMinor)
			assert.Equal(t, tc.wantOK, ok)
			if tc.wantOK {
				assert.Equal(t, tc.want, got)
			}
		})
	}
}
