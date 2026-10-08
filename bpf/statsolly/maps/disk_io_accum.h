// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

#include <statsolly/types.h>

typedef struct disk_io_key {
    // whole disk
    u32 major;
    u32 minor;
    enum disk_op op;
    // 0 on success; otherwise a blk_status_t or an errno, see disk_status_code
    u8 status;
    u8 _pad[2];
} disk_io_key_t;

// Cumulative values: the kernel never resets them, userspace reads them periodically and
// computes the deltas.
typedef struct disk_io_accum {
    u64 latency_count[k_disk_latency_max_buckets];
    u64 latency_sum_ns[k_disk_latency_max_buckets];
} disk_io_accum_t;

// A plain hash map, not an LRU one: LRU maps evict live entries long before they are full on hosts
// with many CPUs (before Linux 6.16, except from 6.12.39, 6.6.99, RHEL 9.8 and RHEL 10.2, which
// have the fix), and userspace deletes the entries that stay idle, so that the map doesn't fill up
// with the keys of devices that are gone.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 12);
    __type(key, disk_io_key_t);
    __type(value, disk_io_accum_t);
    __uint(pinning, OBI_PIN_INTERNAL);
} disk_io_accum SEC(".maps");
