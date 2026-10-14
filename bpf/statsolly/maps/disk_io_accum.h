// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

#include <statsolly/types.h>

typedef struct disk_io_key {
    // the io controller cgroup that the I/O is charged to, or 0 when it isn't read
    u64 cgroup_id;
    // the whole disk
    u32 major;
    u32 minor;
    enum disk_op op;
    // 0 on success, or else a blk_status_t or an errno (disk_status_code)
    u8 status;
    u8 _pad[6];
} disk_io_key_t;

// Cumulative values: userspace reads them periodically and computes the deltas
typedef struct disk_io_accum {
    u64 latency_count[k_disk_latency_buckets];
    u64 latency_sum_ns;
    // bytes of the successful requests, at their issue
    u64 bytes;
} disk_io_accum_t;

// A hash map, not an LRU one, so that the kernel never evicts the cumulative values
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 12);
    __type(key, disk_io_key_t);
    __type(value, disk_io_accum_t);
    __uint(pinning, OBI_PIN_INTERNAL);
} disk_io_accum SEC(".maps");
