// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

#include <statsolly/types.h>

typedef struct fs_sync_start {
    u64 started_ns;
    enum fs_sync_type type;
    // started by a sync system call, which completes it, rather than by a kernel function
    u8 from_syscall;
    u8 _pad[6];
} fs_sync_start_t;

// The file sync in progress in each thread, keyed by pid_tgid. LRU so that syncs whose return is
// never seen can't leak entries. Userspace sizes it like disk_rq_start, so that an LRU map doesn't
// evict syncs in progress.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1 << 14);
    __type(key, u64);
    __type(value, fs_sync_start_t);
    __uint(pinning, OBI_PIN_INTERNAL);
} fs_sync_start SEC(".maps");
