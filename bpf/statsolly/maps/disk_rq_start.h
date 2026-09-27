// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

#include <statsolly/types.h>

typedef struct disk_rq_start {
    u64 issued_ns;
    // time the request waited before its issue, k_disk_queue_unknown if unknown
    u64 queued_ns;
    // size of the request when it was issued
    u32 bytes;
    // whole disk and operation, for userspace to count the requests in flight
    u32 major;
    u32 minor;
    enum disk_op op;
    u8 _pad[3];
} disk_rq_start_t;

// Each in-flight block request, keyed by the struct request address. Userspace also iterates it
// to count the requests in flight. LRU so that requests whose completion is never seen can't leak
// entries.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1 << 14);
    __type(key, u64);
    __type(value, disk_rq_start_t);
    __uint(pinning, OBI_PIN_INTERNAL);
} disk_rq_start SEC(".maps");
