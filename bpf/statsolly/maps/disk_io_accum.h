// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

#include <statsolly/types.h>

typedef struct disk_io_key {
    // the whole disk
    u32 major;
    u32 minor;
    enum disk_op op;
    u8 _pad[3];
} disk_io_key_t;

// Cumulative values: userspace reads them periodically and computes the deltas
typedef struct disk_io_accum {
    u64 latency_count[k_disk_latency_buckets];
    u64 latency_sum_ns;
} disk_io_accum_t;

// A hash map, not an LRU one, so that the kernel never evicts the cumulative values
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 12);
    __type(key, disk_io_key_t);
    __type(value, disk_io_accum_t);
    __uint(pinning, OBI_PIN_INTERNAL);
} disk_io_accum SEC(".maps");
