// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

#include <statsolly/types.h>

typedef struct disk_io_key {
    // id of the cgroup the I/O is charged to (in the io controller hierarchy), 0 if unknown
    u64 cgroup_id;
    // whole disk
    u32 major;
    u32 minor;
    // partition the I/O targets, as a kernel dev_t, or 0 when it is only known by its number in
    // partno (before Linux 5.11). The whole disk when both are 0 or when part_dev is the disk.
    u32 part_dev;
    enum disk_op op;
    // 0 on success; otherwise a blk_status_t or an errno, see disk_status_code
    u8 status;
    u8 partno;
    u8 _pad[1];
} disk_io_key_t;

// Cumulative values: the kernel never resets them, userspace reads them periodically and
// computes the deltas.
typedef struct disk_io_accum {
    u64 latency_count[k_disk_latency_max_buckets];
    u64 latency_sum_ns[k_disk_latency_max_buckets];
    // time the requests waited before their issue, for those whose wait is known
    u64 queue_count[k_disk_latency_max_buckets];
    u64 queue_sum_ns[k_disk_latency_max_buckets];
    // bytes of the requests that completed successfully
    u64 bytes;
} disk_io_accum_t;

// A plain hash map, not an LRU one: LRU maps evict live entries long before they are full on hosts
// with many CPUs (Linux < 6.16), and userspace deletes the entries that stay idle, so that the map
// doesn't fill up with the keys of workloads and devices that are gone.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 12);
    __type(key, disk_io_key_t);
    __type(value, disk_io_accum_t);
    __uint(pinning, OBI_PIN_INTERNAL);
} disk_io_accum SEC(".maps");
