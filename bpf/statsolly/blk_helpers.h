// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

// Pure helpers of the block request path, kept free of kernel types and map
// access so bpf/tests can check them natively.

// What a request is, as far as the metrics care. The first four are the
// values of enum blk_io_op (bpf/statsolly/types.h) that reach userspace; an
// ignored request (zone management, driver-private operations) never does.
enum blk_req_kind : u8 {
    blk_req_read = 0,
    blk_req_write = 1,
    blk_req_flush = 2,
    blk_req_discard = 3,
    blk_req_ignore = 4,
};

// The request's operation lives in the low bits of cmd_flags. These REQ_OP_*
// values are the same on every supported kernel; the zone operations are not
// (REQ_OP_ZONE_APPEND is 13 in enum req_opf and 7 in its successor enum req_op,
// which RHEL 9 backports), so the caller resolves REQ_OP_ZONE_APPEND through
// CO-RE.
enum {
    k_req_op_mask = 0xff,
    k_req_op_read = 0,
    k_req_op_write = 1,
    k_req_op_flush = 2,
    k_req_op_discard = 3,
    k_req_op_secure_erase = 5,
    k_req_op_write_zeroes = 9,
    // Passed as zone_append on a kernel without REQ_OP_ZONE_APPEND: no masked
    // operation can equal it.
    k_req_op_absent = k_req_op_mask + 1,
};

// A data write that carries REQ_PREFLUSH is still a write: the flush machinery
// issues the flush as a request of its own (REQ_OP_FLUSH), which is what
// counts as a flush. A secure erase is counted as a discard: both release
// blocks rather than move data.
//
// Against /proc/diskstats: flushes match its flushes. Writes match its writes
// with two exceptions. diskstats also counts as a write an empty REQ_PREFLUSH
// write (0 bytes, such as a dm-thin metadata commit or a flush passed through a
// loop device); such a request never reaches block_rq_issue, only the flush
// issued for it does (none on a device without a write-back cache), so it is
// counted here as a flush only. And diskstats counts a secure erase as a
// write, where it is a discard here.
//
// The classic-tracepoint fallback classifies from rwbs instead (below), which
// has no letter for REQ_OP_WRITE_ZEROES or REQ_OP_ZONE_APPEND: they are
// ignored there, while this raw path counts them as writes.
static __always_inline enum blk_req_kind blk_kind_from_cmd_flags(const u32 cmd_flags,
                                                                 const u32 zone_append) {
    const u32 op = cmd_flags & k_req_op_mask;
    switch (op) {
    case k_req_op_read:
        return blk_req_read;
    case k_req_op_write:
    case k_req_op_write_zeroes:
        return blk_req_write;
    case k_req_op_flush:
        return blk_req_flush;
    case k_req_op_discard:
    case k_req_op_secure_erase:
        return blk_req_discard;
    default:
        return op == zone_append ? blk_req_write : blk_req_ignore;
    }
}

// The classic tracepoint hands over the rwbs string instead (blk_fill_rwbs):
// an 'F' for REQ_PREFLUSH comes first, then the operation's letter: 'W'
// write, 'R' read, 'D' discard (secure erase is "DE"), 'F' flush and 'N' any
// operation without a letter of its own. So "FW" is a write with a preflush,
// and an 'F' followed by anything else is a flush. REQ_OP_WRITE_ZEROES and
// REQ_OP_ZONE_APPEND are 'N', so this path ignores them.
static __always_inline enum blk_req_kind blk_kind_from_rwbs(const char rwbs0, const char rwbs1) {
    switch (rwbs0) {
    case 'R':
        return blk_req_read;
    case 'W':
        return blk_req_write;
    case 'D':
        return blk_req_discard;
    case 'F':
        return rwbs1 == 'W' ? blk_req_write : blk_req_flush;
    default:
        return blk_req_ignore;
    }
}

// Whether completions of this kind reach userspace. emit_kinds has one bit per
// enum blk_req_kind, set by userspace from the enabled metrics; blk_req_ignore
// never has one.
static __always_inline bool blk_kind_emitted(const u8 emit_kinds, const enum blk_req_kind kind) {
    return (emit_kinds >> kind) & 1;
}

// The classic tracepoint reports an errno; the raw one reports blk_status_t,
// which the kernel maps through its blk_errors table. Mirror the entries an
// operator is likely to meet and treat the rest as generic I/O errors. Values
// are the kernel's BLK_STS_* ABI.
enum {
    k_blk_sts_ok = 0,
    k_blk_sts_notsupp = 1,
    k_blk_sts_timeout = 2,
    k_blk_sts_nospc = 3,
    k_blk_sts_transport = 4,
    k_blk_sts_target = 5,
    k_blk_sts_medium = 7,
    k_blk_sts_resource = 9,
    k_blk_sts_ioerr = 10,
};

static __always_inline int blk_status_to_errno(const u8 status) {
    switch (status) {
    case k_blk_sts_ok:
        return 0;
    case k_blk_sts_notsupp:
        return -95; // EOPNOTSUPP
    case k_blk_sts_timeout:
        return -110; // ETIMEDOUT
    case k_blk_sts_nospc:
        return -28; // ENOSPC
    case k_blk_sts_transport:
        return -67; // ENOLINK
    case k_blk_sts_target:
        return -121; // EREMOTEIO
    case k_blk_sts_medium:
        return -61; // ENODATA
    case k_blk_sts_resource:
        return -12; // ENOMEM
    case k_blk_sts_ioerr:
    default:
        return -5; // EIO
    }
}

// block_rq_complete fires from blk_update_request() once per completed chunk,
// before the request is advanced, so data_len (rq->__data_len) is what was
// left before this chunk. A driver that completes a request piecewise (SCSI
// good_bytes, a medium error in the middle) fires it several times; only the
// chunk that covers the rest, or one that fails, ends the request.
static __always_inline bool
blk_rq_final_chunk(const u32 nr_bytes, const u32 data_len, const u8 status) {
    return nr_bytes >= data_len || status != k_blk_sts_ok;
}

// A request between block_rq_issue and its final block_rq_complete.
struct blk_rq_inflight {
    u64 issue_ns;
    u64 queue_ns;   // block_rq_insert -> block_rq_issue; 0 when never inserted
    u64 bytes_done; // bytes reported by earlier partial completions
    u32 dev;        // kernel dev_t (major<<20 | minor) of the whole disk
    enum blk_req_kind kind;
    unsigned char _pad[3];
};

// blk_rq_reissue updates the entry of a request issued again while its entry
// is still present: a requeued request, or a request struct the kernel reused
// after a completion this program missed. The new issue replaces every field,
// so a stale entry cannot lend its device or kind to an unrelated request.
// Only the bytes of earlier partial completions survive, and only for the same
// device and kind: SCSI requeues the rest of a partially completed request.
//
// Returns the device the entry was counted on until now. Request structs come
// from a tag set, which every namespace of an NVMe controller and every LUN of
// a SCSI host share, so a reused struct can move the entry to another disk,
// and the caller has to move its in-flight count along with it.
static __always_inline u32 blk_rq_reissue(struct blk_rq_inflight *const cur,
                                          const struct blk_rq_inflight *const issued) {
    const u32 prev_dev = cur->dev;
    const bool same_request = prev_dev == issued->dev && cur->kind == issued->kind;
    const u64 bytes_done = same_request ? cur->bytes_done : 0;

    *cur = *issued;
    cur->bytes_done = bytes_done;
    return prev_dev;
}
