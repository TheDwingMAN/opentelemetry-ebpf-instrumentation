// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <statsolly/types.h>

// The latency histogram bounds of the block requests and of the file syncs, injected by userspace
// at load
volatile const u64 disk_latency_bounds_ns[k_disk_latency_bounds];

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

// The status of the errnos that don't fit in a u8, like the kernel-internal ERESTARTSYS (512),
// which userspace names _OTHER
enum { k_status_other = 0xff };

// block_rq_complete reports a negative int errno before Linux 5.16, and a blk_status_t since. The
// status of a request is the blk_status_t, or the errno: 0 on success either way.
static __always_inline u8 disk_status_code(const u64 raw_status, const bool is_blk_status) {
    if (is_blk_status) {
        return (u8)raw_status;
    }
    // the raw tracepoint argument holds the negative int zero-extended
    const u32 errno_value = -(u32)raw_status;
    return errno_value < k_status_other ? (u8)errno_value : k_status_other;
}

// The errnos of the syncs that sync nothing
enum {
    k_errno_ebadf = 9,
    k_errno_einval = 22,
    k_errno_espipe = 29,
};

// A sync fails with EBADF on an invalid file descriptor, and with EINVAL on a file that can't be
// synced, such as a pipe, a socket or a terminal (as a logger syncing its standard output does), or
// on invalid sync_file_range(2) flags or offsets, which fails with ESPIPE on a pipe instead
static __always_inline bool fs_sync_attempted(const s32 ret) {
    return ret != -k_errno_ebadf && ret != -k_errno_einval && ret != -k_errno_espipe;
}

// The flags of sync_file_range(2) (include/uapi/linux/fs.h), which the kernel BTF doesn't have
enum {
    k_sync_file_range_wait_before = 1,
    k_sync_file_range_write = 2,
    k_sync_file_range_wait_after = 4,
};

// sync_file_range(2) with SYNC_FILE_RANGE_WRITE alone, as the flush hints of PostgreSQL and RocksDB,
// starts the writeback without waiting for it: it is not a sync
static __always_inline bool sync_file_range_waits(const u32 flags) {
    return (flags & (k_sync_file_range_wait_before | k_sync_file_range_wait_after)) != 0;
}
