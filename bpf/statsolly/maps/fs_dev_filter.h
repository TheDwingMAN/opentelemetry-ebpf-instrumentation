// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

// Allowlist of local-filesystem (ext4/xfs/btrfs) superblock dev_t values
// backed by a Kubernetes persistent volume mount. Those filesystems also
// back the node's own root filesystem and every container's writable layer,
// so their probes must not record unconditionally; only a device present in
// this map is recorded. Populated from userspace by scanning kubelet volume
// mounts. Plain HASH, not LRU: a device must never be silently evicted, or
// its PV-backed I/O would start being dropped as if it were unlisted.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 12);
    __type(key, u32);
    __type(value, u8);
    __uint(pinning, OBI_PIN_INTERNAL);
} fs_dev_filter SEC(".maps");
