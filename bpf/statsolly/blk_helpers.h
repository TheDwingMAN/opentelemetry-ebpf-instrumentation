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

// A bio submitted to a stacked volume (dm, md) carries the same operation and
// flags in bi_opf, but there is no flush machinery above a bio-based device
// to turn a flush into a request of its own: a flush arrives as an empty
// write with REQ_PREFLUSH (blkdev_issue_flush; S0-b: op WRITE, bi_size 0,
// REQ_PREFLUSH set, REQ_FUA clear), and that bio is the flush. A write that
// carries data is a write whatever its flags: a journal commit is
// REQ_PREFLUSH | REQ_FUA with data. preflush_mask is REQ_PREFLUSH, whose bit
// has moved between kernels, so the caller resolves it through CO-RE; 0, on a
// kernel whose BTF does not name it, makes every empty write a flush, which
// is what the block layer itself takes a write without sectors for.
static __always_inline enum blk_req_kind
blk_kind_from_bio(const u32 opf, const u32 size, const u32 zone_append, const u32 preflush_mask) {
    const bool empty_write = (opf & k_req_op_mask) == k_req_op_write && size == 0;
    if (empty_write && (preflush_mask == 0 || (opf & preflush_mask))) {
        return blk_req_flush;
    }
    return blk_kind_from_cmd_flags(opf, zone_append);
}

// Reads and writes, the only kinds with a disk.io.direction: they alone feed
// the read/write metrics and the queue wait.
static __always_inline bool blk_kind_is_read_write(const enum blk_req_kind kind) {
    return kind == blk_req_read || kind == blk_req_write;
}

// Whether completions of this kind reach userspace. emit_kinds has one bit per
// enum blk_req_kind, set by userspace from the enabled metrics; blk_req_ignore
// never has one.
static __always_inline bool blk_kind_emitted(const u8 emit_kinds, const enum blk_req_kind kind) {
    return (emit_kinds >> kind) & 1;
}

// The classic tracepoint reports an errno. The raw one reports blk_status_t
// since Linux 5.16 (and on RHEL 9), which the kernel maps through its
// blk_errors table; mirror the entries an operator is likely to meet and treat
// the rest as generic I/O errors. Values are the kernel's BLK_STS_* ABI.
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

// blk_complete_error turns block_rq_complete's error argument, as the
// tracepoint passes it (zero- or sign-extended to 64 bits), into a negative
// errno or 0. Kernels before 5.16 pass an int errno (is_errno, which the
// loader reads from the tracepoint's BTF prototype); later ones a
// blk_status_t, whose one byte must not be read as an errno: EOPNOTSUPP (-95)
// is 0xa1 as a byte, which is no BLK_STS_* value, so it would read as EIO.
static __always_inline int blk_complete_error(const u64 arg, const bool is_errno) {
    if (is_errno) {
        return (int)arg;
    }
    return blk_status_to_errno((u8)arg);
}

// block_rq_complete fires from blk_update_request() once per completed chunk,
// before the request is advanced, so data_len (rq->__data_len) is what was
// left before this chunk. A driver that completes a request piecewise (SCSI
// good_bytes, a medium error in the middle) fires it several times; only the
// chunk that covers the rest, or one that fails, ends the request.
static __always_inline bool
blk_rq_final_chunk(const u32 nr_bytes, const u32 data_len, const int error) {
    return nr_bytes >= data_len || error != 0;
}

// blk_start_if_valid returns rq->start_time_ns when it is a fresh accounting
// start, else 0. blk_account_io_start writes the field and sets RQF_IO_STAT in
// one block, and request structs are reused per tag with rq_flags reset on
// every allocation, so with queue/iostats=0 the field keeps a stale value from
// an earlier use of the tag (S0-a: 1 to 42 s old) that a start_ns != 0 test
// passes. Only the flag tells fresh from stale. A write in the flush machine
// (RQF_FLUSH_SEQ) is excluded: its start precedes the PREFLUSH it waited
// behind, so the interval is that flush's service time, not queueing (the same
// condition blk_account_io_done uses for diskstats). A zero mask is a kernel
// whose BTF has no enum rqf_flags: no queue time.
static __always_inline u64 blk_start_if_valid(const u32 rq_flags,
                                              const u32 io_stat_mask,
                                              const u32 flush_seq_mask,
                                              const u64 start_ns) {
    if (io_stat_mask == 0) {
        return 0;
    }
    if ((rq_flags & (io_stat_mask | flush_seq_mask)) != io_stat_mask) {
        return 0;
    }
    return start_ns;
}

// blk_queue_ns is the queue interval of a request issued at issue_ns whose
// valid start is start_ns (0 when it has none). A start after the issue is
// impossible for a fresh value (0 of about 8.6M requests in S0-a) and is
// dropped rather than wrapped. The result is at least 1 ns, because 0 means
// "no queue time" to the aggregation and the exporters.
static __always_inline u64 blk_queue_ns(const u64 start_ns, const u64 issue_ns) {
    if (start_ns == 0 || start_ns > issue_ns) {
        return 0;
    }
    const u64 queue_ns = issue_ns - start_ns;
    return queue_ns ? queue_ns : 1;
}

// A request between block_rq_issue and its final block_rq_complete, or a bio
// of a stacked volume between block_bio_queue and block_bio_complete: both
// in-flight maps hold this value, so one snapshot reader counts either as
// pending.
struct blk_rq_inflight {
    u64 issue_ns; // block_rq_issue, or block_bio_queue for a bio
    u64 queue_ns; // start_time_ns -> block_rq_issue; 0 when the start is not valid, and for a bio
    // Bytes reported by earlier partial completions. For a bio, its size when
    // it was queued: a bio completes once, and its size is consumed by then.
    u64 bytes_done;
    // Id of the cgroup the I/O is charged to (its blkcg's cgroup v2 id), read
    // at the issue or queueing of a read or write only when storage_block_pod
    // is on; 0 when off, for other kinds and when the request has none.
    u64 cgid;
    u32 dev;      // kernel dev_t (major<<20 | minor) of the whole disk
    u32 part_dev; // partition dev_t; 0 for whole-disk I/O, read only when selected
    enum blk_req_kind kind;
    unsigned char _pad[7];
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

// blk_bio_requeue updates the entry of a bio pointer queued while an entry
// is still present. The block layer traces the queueing of a bio once
// (BIO_TRACE_COMPLETION), so this is never the same bio again: it is a new
// bio in a struct the kernel reused after a completion this program missed.
// Every field is replaced, the bytes included: nothing of the earlier bio
// belongs to this one.
//
// Returns the device the entry was counted on until now, as blk_rq_reissue.
static __always_inline u32 blk_bio_requeue(struct blk_rq_inflight *const cur,
                                           const struct blk_rq_inflight *const queued) {
    const u32 prev_dev = cur->dev;
    *cur = *queued;
    return prev_dev;
}

// The key of the kernel aggregation maps (maps/blk_agg.h, maps/blk_q_agg.h):
// one per device, request kind and errno. The errno in the key stands in for
// a separate error map: userspace sums the keys with err != 0 into
// operation.errors and keeps err as the error.type of flush and discard.
struct blk_agg_key {
    u32 dev;      // kernel dev_t of the whole disk
    u32 part_dev; // partition dev_t; 0 for whole-disk I/O and until partitions are resolved
    enum blk_req_kind kind;
    u8 _pad;
    u16 err; // errno, positive; 0 on success
    u32 _pad2;
};

// blk_agg_err turns a completion's error (0 or a negative errno) into the
// key's errno. Errnos, the kernel-internal ones (512-530) included, fit in
// 16 bits; anything larger is clamped rather than wrapped onto another errno.
enum { k_blk_agg_err_max = (u16)~0 };

static __always_inline u16 blk_agg_err(const int error) {
    const u32 err = error < 0 ? (u32)(-(s64)error) : (u32)error;
    return err > k_blk_agg_err_max ? k_blk_agg_err_max : (u16)err;
}

static __always_inline struct blk_agg_key blk_agg_key_of(const struct blk_rq_inflight *const rq,
                                                         const int error) {
    struct blk_agg_key key = {};
    key.dev = rq->dev;
    key.part_dev = rq->part_dev;
    key.kind = rq->kind;
    key.err = blk_agg_err(error);
    return key;
}

// The key of the pod counters (maps/blk_cg_agg.h): one per cgroup the I/O
// is charged to, device and direction. The partition is 0 unless
// obi.disk.partition is selected, as in the in-flight value.
struct blk_cg_key {
    u64 cgid;
    u32 dev;
    u32 part_dev;
    enum blk_req_kind kind; // blk_req_read or blk_req_write
    unsigned char _pad[7];
};

static __always_inline struct blk_cg_key blk_cg_key_of(const struct blk_rq_inflight *const op) {
    struct blk_cg_key key = {};
    key.cgid = op->cgid;
    key.dev = op->dev;
    key.part_dev = op->part_dev;
    key.kind = op->kind;
    return key;
}

// blk_op_time_ns is what a completed operation adds to
// obi.stat.disk.operation_time, the time diskstats fields 7 and 11 count:
// from the request's accounting start when it has a valid one (queue_ns, its
// start -> issue, is then not 0), else from its issue (svc_ns, issue ->
// completion). A bio has no queue wait: it is timed from its queueing. A
// start equal to the issue is a queue wait of 1 ns (blk_queue_ns), which
// adds that 1 ns.
static __always_inline u64 blk_op_time_ns(const u64 svc_ns, const u64 queue_ns) {
    return svc_ns + queue_ns;
}

// blk_part_dev is the partition dev_t to report for a request whose first
// bio or, lacking one, rq->part named pdev: 0 for whole-disk I/O (pdev ==
// dev, the gendisk's own devt) or an unresolved partition (pdev == 0), so
// obi.disk.partition is omitted for both rather than set to the disk's own
// device.
static __always_inline u32 blk_part_dev(const u32 pdev, const u32 dev) {
    return pdev == dev ? 0 : pdev;
}

// The dev_t of a whole disk, from its gendisk: disk_devt(), which is
// MKDEV(major, first_minor).
enum { k_minorbits = 20 }; // MINORBITS: dev_t is major << 20 | minor

static __always_inline u32 blk_disk_devt(const int major, const int first_minor) {
    return ((u32)major << k_minorbits) | (u32)first_minor;
}

// The bio programs run for every bio submitted on the node, and nearly all of
// them go to devices that are not tracked volumes. Before the lookup in the
// set of tracked volumes, the major of the bio's gendisk is compared with the
// majors that set has devices of, which userspace keeps here: device-mapper's
// (dynamic), md's (9) and, for old partitionable arrays, mdp's. An unused
// slot is 0, which never matches: no disk has major 0 (one registered without
// a major gets the extended block major), and 0 is what a failed read of the
// gendisk returns.
//
// It has to be the gendisk's major, not that of the bio's block_device: a
// partition of an md array is 259:N (the extended block major) while its disk
// is 9:M, and a filter on the partition's number would drop it (S0-b).
enum { k_blk_vol_majors = 3 };

static __always_inline bool blk_vol_major_match(const u32 *const majors, const u32 major) {
    return major != 0 && (major == majors[0] || major == majors[1] || major == majors[2]);
}
