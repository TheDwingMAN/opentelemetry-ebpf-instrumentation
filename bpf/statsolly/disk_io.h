// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <statsolly/types.h>

// Index of the histogram bucket that holds latency_ns. Buckets are upper-inclusive, like
// Prometheus "le" buckets and OTel explicit bucket histograms: bucket i holds values in
// (bounds[i-1], bounds[i]], and the last bucket holds everything above the last bound.
// bounds must be sorted in ascending order, so the index is the number of bounds below
// latency_ns.
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

// REQ_OP_* values of the operations that are measured. They are stable across kernel versions,
// unlike REQ_OP_ZONE_APPEND (13, 21 or 7), which userspace finds in the kernel BTF. enum req_opf
// was renamed enum req_op, so none of them is relocated.
enum {
    k_req_op_read = 0,
    k_req_op_write = 1,
    k_req_op_flush = 2,
    k_req_op_write_zeroes = 9,
};

// disk_op_from_req_op classifies the REQ_OP_* operation of a request. Writing zeroes and appending
// to a zone count as writes, as /proc/diskstats counts them. Cache flushes are measured; discards
// are not. zone_append_op is REQ_OP_ZONE_APPEND, or 0 when the kernel has none: reads are
// classified first, so 0 matches nothing.
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
    default:
        return req_op == zone_append_op ? disk_op_write : disk_op_unknown;
    }
}

// disk_accounted_start_ns is the start of a request (rq->start_time_ns) if the kernel accounts it
// (io_stat_flag, RQF_IO_STAT, in rq_flags), and 0 (unknown) otherwise. From Linux 6.13, the kernel
// writes the start only when it accounts the request, so a request reused on a device that doesn't
// keep I/O statistics keeps the start of an earlier use. io_stat_flag is 0 on the kernels that
// write the time or 0 at every allocation, which need no check. The flush that a flush sequence
// sends (flush_seq_flag, RQF_FLUSH_SEQ) has no RQF_IO_STAT, but the kernel accounts every such
// flush, from the start that it writes whenever the sequence sends the flush.
static __always_inline u64 disk_accounted_start_ns(const u64 start_ns,
                                                   const u32 rq_flags,
                                                   const u32 io_stat_flag,
                                                   const u32 flush_seq_flag) {
    if (io_stat_flag != 0 && (rq_flags & (io_stat_flag | flush_seq_flag)) == 0) {
        return 0;
    }
    return start_ns;
}

// A request can complete in several block_rq_complete calls (partial completions). Each call
// reports the bytes completed by that call while remaining_bytes (rq->__data_len) still
// holds the bytes left before the call, so the call that completes the rest is the last one. A
// failed call that leaves bytes is not: the kernel retries the rest, or fails it in another call,
// as SCSI does with the part of a mixed merge that failed.
static __always_inline bool disk_rq_final_completion(const u32 nr_bytes,
                                                     const u32 remaining_bytes) {
    return nr_bytes >= remaining_bytes;
}

// disk_rq_completed_before tells whether a request ends after an earlier completion completed all
// its bytes, as device mapper ends a request of a request-based volume (dm-multipath) once its clone
// completed on a path. The kernel leaves rq->biotail set when it completes the last bio, but clears
// it with rq->bio when NVMe multipath takes the bios of a request to retry them on another path:
// that ending is the only completion of the request.
static __always_inline bool
disk_rq_completed_before(const u32 nr_bytes, const bool has_bio, const bool has_biotail) {
    return nr_bytes == 0 && !has_bio && has_biotail;
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
