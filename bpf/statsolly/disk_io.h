// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <statsolly/types.h>

// The histogram bucket of latency_ns. Buckets are upper-inclusive, like Prometheus "le" buckets:
// bucket i holds the values in (bounds[i-1], bounds[i]], and the last bucket the values above the
// last bound. bounds are sorted in ascending order.
static __always_inline u32 disk_latency_bucket(const volatile u64 *bounds, const u64 latency_ns) {
    u32 bucket = 0;
#pragma unroll
    for (u32 i = 0; i < k_disk_latency_bounds; i++) {
        if (latency_ns > bounds[i]) {
            bucket = i + 1;
        }
    }
    return bucket;
}

// The REQ_OP_* values of the measured operations, which are stable across kernel versions
enum {
    k_req_op_read = 0,
    k_req_op_write = 1,
    k_req_op_write_zeroes = 9,
};

// Writing zeroes counts as a write, as in /proc/diskstats
static __always_inline enum disk_op disk_op_from_req_op(const u32 req_op) {
    switch (req_op) {
    case k_req_op_read:
        return disk_op_read;
    case k_req_op_write:
    case k_req_op_write_zeroes:
        return disk_op_write;
    default:
        return disk_op_unknown;
    }
}

// A request can complete in several block_rq_complete calls. Each call reports the bytes that it
// completed while remaining_bytes (rq->__data_len) still holds the bytes left before it, so the call
// that completes the rest is the final one. A failed call that leaves bytes is not: the kernel
// retries the rest, or fails it in another call.
static __always_inline bool disk_rq_final_completion(const u32 nr_bytes,
                                                     const u32 remaining_bytes) {
    return nr_bytes >= remaining_bytes;
}
