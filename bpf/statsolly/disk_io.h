// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <statsolly/types.h>

// Index of the histogram bucket that holds latency_ns. Buckets are upper-inclusive, like
// Prometheus "le" buckets and OTel explicit bucket histograms: bucket i holds values in
// (bounds[i-1], bounds[i]], and the last bucket holds everything above bounds[bounds_len-1].
// bounds must be sorted in ascending order, so the index is the number of bounds below
// latency_ns.
static __always_inline u32 disk_latency_bucket(const volatile u64 *bounds,
                                               const u32 bounds_len,
                                               const u64 latency_ns) {
    u32 bucket = 0;
#pragma unroll
    for (u32 i = 0; i < k_disk_latency_max_bounds; i++) {
        if (i < bounds_len && latency_ns > bounds[i]) {
            bucket = i + 1;
        }
    }
    return bucket;
}

// A request can complete in several block_rq_complete calls (partial completions). Each call
// reports the bytes completed by that call while remaining_bytes (rq->__data_len) still
// holds the bytes left before the call, so the call that completes the rest is the last one.
static __always_inline bool
disk_rq_final_completion(const u32 nr_bytes, const u32 remaining_bytes, const u8 status) {
    return status != 0 || nr_bytes >= remaining_bytes;
}

// block_rq_complete reports a negative errno before Linux 5.16 and a blk_status_t since.
// Both are normalized to a small positive code: the blk_status_t value, or the errno.
static __always_inline u8 disk_status_code(const u64 raw_error, const bool is_blk_status) {
    if (is_blk_status) {
        return (u8)raw_error;
    }
    return (u8)(-(s32)raw_error);
}
