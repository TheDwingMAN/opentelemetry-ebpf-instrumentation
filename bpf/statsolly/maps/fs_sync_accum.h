// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

#include <statsolly/types.h>

typedef struct fs_sync_key {
    // id of the io controller cgroup of the thread that synced the file, 0 if unknown
    u64 cgroup_id;
    // 0 on success, otherwise the errno
    u8 status;
    u8 _pad[7];
} fs_sync_key_t;

// Cumulative values: the kernel never resets them, userspace reads them periodically and
// computes the deltas.
typedef struct fs_sync_accum {
    u64 latency_count[k_disk_latency_max_buckets];
    u64 latency_sum_ns[k_disk_latency_max_buckets];
} fs_sync_accum_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1 << 12);
    __type(key, fs_sync_key_t);
    __type(value, fs_sync_accum_t);
    __uint(pinning, OBI_PIN_INTERNAL);
} fs_sync_accum SEC(".maps");
