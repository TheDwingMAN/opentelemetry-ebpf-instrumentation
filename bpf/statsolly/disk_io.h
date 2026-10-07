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

// REQ_OP_* values of the operations that are measured. They are stable across kernel versions,
// unlike REQ_OP_ZONE_APPEND (13, 21 or 7), which userspace finds in the kernel BTF. enum req_opf
// was renamed enum req_op, so none of them is relocated.
enum {
    k_req_op_read = 0,
    k_req_op_write = 1,
    k_req_op_flush = 2,
    k_req_op_discard = 3,
    k_req_op_secure_erase = 5,
    k_req_op_write_zeroes = 9,
};

// disk_op_from_req_op classifies the REQ_OP_* operation of a request. A secure erase discards
// the blocks too, so it counts as a discard. Writing zeroes and appending to a zone count as
// writes, as /proc/diskstats counts them. zone_append_op is REQ_OP_ZONE_APPEND, or 0 when the
// kernel has none: reads are classified first, so 0 matches nothing.
static __always_inline enum disk_op disk_op_from_req_op(const u32 req_op,
                                                        const u32 zone_append_op) {
    switch (req_op) {
    case k_req_op_read:
        return disk_op_read;
    case k_req_op_write:
    case k_req_op_write_zeroes:
        return disk_op_write;
    case k_req_op_flush:
        return disk_op_flush;
    case k_req_op_discard:
    case k_req_op_secure_erase:
        return disk_op_discard;
    default:
        return req_op == zone_append_op ? disk_op_write : disk_op_unknown;
    }
}

// disk_bio_op classifies a bio from its operation and flags. File systems flush the cache of
// a device with an empty write that has the preflush flag.
static __always_inline enum disk_op disk_bio_op(const u32 opf,
                                                const u32 op_mask,
                                                const u32 preflush_flag,
                                                const u32 zone_append_op,
                                                const u32 size) {
    const enum disk_op op = disk_op_from_req_op(opf & op_mask, zone_append_op);
    if (op == disk_op_write && size == 0 && (opf & preflush_flag)) {
        return disk_op_flush;
    }
    return op;
}

enum { k_disk_queue_unknown = ~0ULL };

// disk_queue_ns is the time a request waited in the block layer, from its allocation until its
// issue to the device: in the I/O scheduler or in the dispatch queues. The kernel only records
// the allocation time (start_ns) when I/O statistics or an I/O scheduler need it, so the wait is
// k_disk_queue_unknown when start_ns is 0.
static __always_inline u64 disk_queue_ns(const u64 start_ns, const u64 issue_ns) {
    if (start_ns == 0 || start_ns > issue_ns) {
        return k_disk_queue_unknown;
    }
    return issue_ns - start_ns;
}

// A request can complete in several block_rq_complete calls (partial completions). Each call
// reports the bytes completed by that call while remaining_bytes (rq->__data_len) still
// holds the bytes left before the call, so the call that completes the rest is the last one.
static __always_inline bool
disk_rq_final_completion(const u32 nr_bytes, const u32 remaining_bytes, const u8 status) {
    return status != 0 || nr_bytes >= remaining_bytes;
}

enum { k_sector_shift = 9 };

// disk_rq_bytes is the size of a request that the kernel timed, at its final completion. The
// kernel records the size at the issue in 512-byte sectors on 16 bits (rq->stats_sectors), which
// wraps above 32 MiB, while the final completion reports the bytes it completes: all of them
// unless the request completed in several parts. The larger of the two is the size, except for
// requests both larger than 32 MiB and completed in parts.
static __always_inline u32 disk_rq_bytes(const u32 completed_bytes, const u16 stats_sectors) {
    const u32 issued_bytes = (u32)stats_sectors << k_sector_shift;
    return completed_bytes > issued_bytes ? completed_bytes : issued_bytes;
}

// The status of errnos that don't fit in a u8, such as the kernel-internal ERESTARTSYS (512),
// which userspace reports as _OTHER
enum { k_status_other = 0xff };

static __always_inline u8 errno_status(const u32 errno) {
    return errno < k_status_other ? (u8)errno : (u8)k_status_other;
}

// block_rq_complete reports a negative errno before Linux 5.16 and a blk_status_t since.
// Both are normalized to a small positive code: the blk_status_t value, or the errno.
static __always_inline u8 disk_status_code(const u64 raw_error, const bool is_blk_status) {
    if (is_blk_status) {
        return (u8)raw_error;
    }
    return errno_status((u32)(-(s32)raw_error));
}

enum { k_errno_ebadf = 9 };

// do_fsync fails with EBADF, before syncing anything, when the file descriptor is invalid
static __always_inline bool fs_sync_attempted(const s32 ret) {
    return ret != -k_errno_ebadf;
}

// The flags of sync_file_range(2), from include/uapi/linux/fs.h. They are preprocessor constants:
// the kernel BTF doesn't have them.
enum {
    k_sync_file_range_wait_before = 1,
    k_sync_file_range_write = 2,
    k_sync_file_range_wait_after = 4,
};

// sync_file_range(2) only waits for the writeback with SYNC_FILE_RANGE_WAIT_BEFORE or
// SYNC_FILE_RANGE_WAIT_AFTER. SYNC_FILE_RANGE_WRITE alone, as the flush hints of PostgreSQL and
// RocksDB do, starts the writeback and returns: it is not a sync.
static __always_inline bool sync_file_range_waits(const u32 flags) {
    return (flags & (k_sync_file_range_wait_before | k_sync_file_range_wait_after)) != 0;
}

// vfs_fsync_range returns 0 or a negative errno. Normalized to the errno, 0 on success.
static __always_inline u8 fs_sync_status(const s32 ret) {
    if (ret >= 0) {
        return 0;
    }
    return errno_status((u32)(-ret));
}
