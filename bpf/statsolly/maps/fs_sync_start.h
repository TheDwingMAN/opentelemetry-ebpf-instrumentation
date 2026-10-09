// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

#include <statsolly/types.h>

typedef struct fs_sync_start {
    u64 started_ns;
    // kernel dev_t of the filesystem being synced, 0 for all of them (sync) or if unknown
    u32 s_dev;
    enum fs_sync_type type;
    // started by a sync system call, which completes it, rather than by a kernel function
    u8 from_syscall;
    u8 _pad[2];
} fs_sync_start_t;

// The file sync in progress in each thread, keyed by pid_tgid. Large enough for an LRU map not to
// evict syncs in progress on hosts with up to 128 CPUs, see disk_cgroup_names.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1 << 14);
    __type(key, u64);
    __type(value, fs_sync_start_t);
    __uint(pinning, OBI_PIN_INTERNAL);
} fs_sync_start SEC(".maps");
