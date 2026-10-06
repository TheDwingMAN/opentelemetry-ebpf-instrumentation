// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_core_read.h>
#include <bpfcore/bpf_tracing.h>

#include <logger/bpf_dbg.h>

#include <statsolly/types.h>
#include <statsolly/blk_helpers.h>
#include <statsolly/blk_cgroup.h>
#include <statsolly/blk_record.h>
#include <statsolly/maps/blk_rq_inflight.h>
#include <statsolly/maps/blk_q_agg.h>
#include <statsolly/hist.h>

// The block request programs: a request enters blk_rq_inflight at
// block_rq_issue and leaves it at its final block_rq_complete. What they
// share with the bio programs of stacked volumes is in blk_record.h.

enum { k_blk_bytes_per_sector = 512 };

// Set by userspace when obi.stat.disk.queue.duration is enabled. When 0 the
// issue does not read the request's accounting start. There is no insert
// program: the queue interval is start_time_ns -> issue, read at issue.
volatile const u8 blk_want_queue;

// blk_agg_zero (blk_record.h) is the zeroed value a new key of the queue maps
// starts from, too.
_Static_assert(sizeof(struct blk_agg_exp_val) >= sizeof(struct blk_queue_agg_exp_val),
               "blk_agg_zero must cover every aggregation value");

// Newer kernels renamed the completion tracepoint context struct
// (trace_event_raw_block_rq_complete -> ..._completion). CO-RE flavor: only
// the fields we access; ___x is ignored in BTF name matching. The request's
// kind comes from block_rq_issue, so rwbs, whose length varies between kernels
// (char[8] in bpfcore/vmlinux.h, char[9] on RHEL 9), is not read here.
// Field order chosen (dev, nr_sector, sector, error, explicit pad) so no
// implicit padding is inserted: -Wpadded is enabled build-wide, and CO-RE
// relocates by field name, not struct layout, so reordering here is safe.
struct trace_event_raw_block_rq_completion___x {
    dev_t dev;
    unsigned int nr_sector;
    sector_t sector;
    int error;
    unsigned char _pad[4];
} __attribute__((preserve_access_index));

// The request flags that say whether rq->start_time_ns is fresh. enum rqf_flags
// is in BTF on kernels that define the flags as bit positions (RHEL 9, Linux
// 5.14+); it is absent on RHEL 8 and older, where there are only macros. Both
// values are bit positions, resolved by CO-RE, so a kernel that renumbers them
// is followed and one without the enum reads as mask 0: no queue time.
enum rqf_flags___x {
    __RQF_FLUSH_SEQ___x = 1,
    __RQF_IO_STAT___x = 8,
};

static __always_inline u32 blk_rqf_io_stat_mask(void) {
    if (bpf_core_enum_value_exists(enum rqf_flags___x, __RQF_IO_STAT___x)) {
        return 1U << bpf_core_enum_value(enum rqf_flags___x, __RQF_IO_STAT___x);
    }
    return 0;
}

static __always_inline u32 blk_rqf_flush_seq_mask(void) {
    if (bpf_core_enum_value_exists(enum rqf_flags___x, __RQF_FLUSH_SEQ___x)) {
        return 1U << bpf_core_enum_value(enum rqf_flags___x, __RQF_FLUSH_SEQ___x);
    }
    return 0;
}

// Whether the issue reads the request's accounting start: queue.duration is
// measured from it, and obi.stat.disk.operation_time (storage_block_pod) from
// it when it is valid.
static __always_inline bool blk_want_start(void) {
    return blk_want_queue || blk_want_cgroup;
}

// blk_rq_start reads the accounting start of a request with the valid-start
// rule of blk_helpers.h: 0 when nothing measures from it, the flags are
// unknown or say the field is stale.
static __always_inline u64 blk_rq_start(const u32 rq_flags, const u64 start_ns) {
    if (!blk_want_start()) {
        return 0;
    }
    return blk_start_if_valid(rq_flags, blk_rqf_io_stat_mask(), blk_rqf_flush_seq_mask(), start_ns);
}

static __always_inline void blk_on_issue(void *const inflight_map,
                                         const void *const key,
                                         const u32 dev,
                                         const u32 part_dev,
                                         const u64 start_ns,
                                         const enum blk_req_kind kind,
                                         const u64 cgid) {
    struct blk_rq_inflight issued = {};
    issued.issue_ns = bpf_ktime_get_ns();
    issued.queue_ns = blk_queue_ns(start_ns, issued.issue_ns);
    issued.cgid = cgid;
    issued.dev = dev;
    issued.part_dev = part_dev;
    issued.kind = kind;

    blk_inflight_begin(inflight_map, key, &issued, false, k_stats_drop_blk_inflight);
}

static __always_inline void blk_agg_queue(const struct blk_agg_key *const key, const u64 queue_ns) {
    if (blk_hist_exp) {
        struct blk_queue_agg_exp_val *const v =
            blk_agg_lookup_or_init(&blk_q_agg_exp, key, k_stats_drop_blk_queue_agg);
        if (!v) {
            return;
        }
        blk_agg_add(&v->queue_sum_ns, queue_ns);
        stat_hist_exp_add(v->queue_bkt, stat_hist_exp_idx(blk_exp_bounds_ns, queue_ns));
        return;
    }

    struct blk_queue_agg_val *const v =
        blk_agg_lookup_or_init(&blk_q_agg, key, k_stats_drop_blk_queue_agg);
    if (!v) {
        return;
    }
    blk_agg_add(&v->queue_sum_ns, queue_ns);
    stat_hist_add(v->queue_bkt, stat_hist_idx(blk_bounds_ns, queue_ns));
}

// blk_aggregate counts a completed request in the kernel maps, as the
// per-event exporters would count its event: service time and bytes for every
// kind, the queue wait for reads and writes that have one (a queue wait of 0
// means the request has no valid accounting start, and the exporters skip it
// too). The queue wait is read for operation_time too, but counted only when
// queue.duration is on: its map has one entry otherwise.
static __always_inline void blk_aggregate(const struct blk_rq_inflight *const rq,
                                          const u64 bytes,
                                          const u64 svc_ns,
                                          const int error) {
    const struct blk_agg_key key = blk_agg_key_of(rq, error);
    blk_agg_service(&key, bytes, svc_ns);

    if (blk_want_queue && rq->queue_ns != 0 && blk_kind_is_read_write(rq->kind)) {
        blk_agg_queue(&key, rq->queue_ns);
    }
}

static __always_inline void blk_on_complete(void *const inflight_map,
                                            const void *const key,
                                            const u32 nr_bytes,
                                            const bool final,
                                            const int error) {
    struct blk_done done;
    if (!blk_inflight_end(inflight_map, key, nr_bytes, final, &done)) {
        return;
    }
    if (blk_emit_mode == k_blk_emit_agg) {
        blk_aggregate(&done.op, done.bytes, done.svc_ns, error);
        return;
    }
    blk_emit_event(&done, error);
}

// Load-time constant: block_rq_complete passes an int errno rather than a
// blk_status_t (kernels before 5.16), as the loader reads from the
// tracepoint's BTF prototype.
volatile const u8 blk_complete_errno;

// The request tracepoints are attached in one of three ways. tp_btf, the
// default, reads the request with direct loads, which the verifier types
// from BTF; raw_tp, its fallback when a tp_btf program cannot be loaded or
// attached, reads it through bpf_probe_read_kernel (BPF_CORE_READ), about a
// quarter slower per run. Both key requests by pointer. The classic
// tracepoints, for kernels whose BTF cannot decode a request, see only
// (dev, sector). Kernels before 5.11 (unless backported, as in 5.10.137 and
// RHEL 8.6) pass the request queue before the request to block_rq_issue; the
// _legacy programs take that shape, and the loader picks the variant the
// tracepoint's BTF prototype has.
//
// The device is the request's gendisk (disk_devt: MKDEV(major, first_minor)),
// as the classic tracepoint names it, so every attach mode names the whole
// disk rather than the partition, and a flush request, which has no
// partition, still names its disk. Kernels before 5.15 keep the gendisk on
// the request (rq_disk); since 5.15, and on RHEL 9 which backports it, it
// lives on the queue. Which one exists is decided at load time by CO-RE, and
// the untaken branch is dead code to the verifier.
// blk_rq_dev reads the device through bpf_probe_read_kernel, for raw_tp.
static __always_inline u32 blk_rq_dev(const struct request *const rq) {
    struct gendisk *disk = NULL;
    if (bpf_core_field_exists(struct request_queue, disk)) {
        disk = BPF_CORE_READ(rq, q, disk);
    } else {
        disk = BPF_CORE_READ(rq, rq_disk);
    }
    if (!disk) {
        return 0;
    }
    return blk_disk_devt(BPF_CORE_READ(disk, major), BPF_CORE_READ(disk, first_minor));
}

// blk_rq_dev_btf reads the device with direct loads, for tp_btf.
static __always_inline u32 blk_rq_dev_btf(const struct request *const rq) {
    struct gendisk *disk = NULL;
    if (bpf_core_field_exists(struct request_queue, disk)) {
        disk = rq->q->disk;
    } else {
        disk = rq->rq_disk;
    }
    if (!disk) {
        return 0;
    }
    return blk_disk_devt(disk->major, disk->first_minor);
}

// blk_rq_part_dev_btf resolves a request's partition dev_t with direct
// loads, when obi.disk.partition is selected (revision 4, from v2
// request_partition, bpf/statsolly/tp_blk.c:54-75, read-order swapped): the
// first bio's block_device (5.12+; bi_bdev is always set and unchanged by
// the kernel's partition-to-whole-disk remap, S0-b) when the request has
// one, else rq->part's (flushes have no bio; rq->part has been a struct
// block_device * since Linux 5.11). blk_part_dev zeroes whole-disk I/O and
// an unresolved partition alike. RHEL 8's hd_struct flavor (rq->part as
// struct hd_struct *, partno only) is not handled: take it only if RHEL 8
// becomes a target.
static __always_inline u32 blk_rq_part_dev_btf(const struct request *const rq, const u32 dev) {
    if (!blk_want_part) {
        return 0;
    }
    struct bio *const bio = rq->bio;
    u32 pdev = 0;
    if (bio && bpf_core_field_exists(bio->bi_bdev)) {
        pdev = bio->bi_bdev->bd_dev;
    } else {
        struct block_device *const part = rq->part;
        if (part) {
            pdev = part->bd_dev;
        }
    }
    return blk_part_dev(pdev, dev);
}

// blk_rq_part_dev reads the same partition through bpf_probe_read_kernel,
// for raw_tp.
static __always_inline u32 blk_rq_part_dev(const struct request *const rq, const u32 dev) {
    if (!blk_want_part) {
        return 0;
    }
    struct bio *const bio = BPF_CORE_READ(rq, bio);
    u32 pdev = 0;
    if (bio && bpf_core_field_exists(bio->bi_bdev)) {
        pdev = BPF_CORE_READ(bio, bi_bdev, bd_dev);
    } else {
        struct block_device *const part = BPF_CORE_READ(rq, part);
        if (part) {
            pdev = BPF_CORE_READ(part, bd_dev);
        }
    }
    return blk_part_dev(pdev, dev);
}

static __always_inline enum blk_req_kind blk_rq_kind(const u32 cmd_flags) {
    return blk_kind_from_cmd_flags(cmd_flags, blk_req_op_zone_append());
}

// Whether the issue of a request of kind reads the cgroup it is charged to:
// only the pod counters use it, and they count reads and writes only.
static __always_inline bool blk_want_cgid(const enum blk_req_kind kind) {
    return blk_want_cgroup && blk_kind_is_read_write(kind);
}

static __always_inline void
blk_rq_complete(const u64 rq, const u32 data_len, const u64 error_arg, const u32 nr_bytes) {
    const int error = blk_complete_error(error_arg, blk_complete_errno);
    blk_on_complete(
        &blk_rq_inflight, &rq, nr_bytes, blk_rq_final_chunk(nr_bytes, data_len, error), error);
}

// tp_btf programs: block_rq_issue(rq) and its legacy (q, rq) shape; block_rq_complete(rq, error, nr_bytes), whose error is a
// blk_status_t or an int errno (blk_complete_errno).

static __always_inline void blk_tp_btf_issue(const struct request *const rq) {
    const u64 key = (u64)rq;
    const u32 dev = blk_rq_dev_btf(rq);
    const enum blk_req_kind kind = blk_rq_kind(rq->cmd_flags);
    blk_on_issue(&blk_rq_inflight,
                 &key,
                 dev,
                 blk_rq_part_dev_btf(rq, dev),
                 blk_rq_start(rq->rq_flags, rq->start_time_ns),
                 kind,
                 blk_want_cgid(kind) ? blk_bio_cgid_btf(rq->bio) : 0);
}

SEC("tp_btf/block_rq_issue")
int BPF_PROG(obi_stats_tp_btf_block_rq_issue, struct request *rq) {
    blk_tp_btf_issue(rq);
    return 0;
}

SEC("tp_btf/block_rq_issue")
int BPF_PROG(obi_stats_tp_btf_block_rq_issue_legacy, struct request_queue *q, struct request *rq) {
    blk_tp_btf_issue(rq);
    return 0;
}

SEC("tp_btf/block_rq_complete")
int BPF_PROG(obi_stats_tp_btf_block_rq_complete,
             struct request *rq,
             unsigned long long error,
             unsigned int nr_bytes) {
    blk_rq_complete((u64)rq, rq->__data_len, error, nr_bytes);
    return 0;
}

// raw_tp programs: the same tracepoints, the request read through
// BPF_CORE_READ.

// blk_raw_tp_start reads the accounting start through bpf_probe_read_kernel
// only when something measures from it.
static __always_inline u64 blk_raw_tp_start(const struct request *const rq) {
    if (!blk_want_start()) {
        return 0;
    }
    return blk_rq_start(BPF_CORE_READ(rq, rq_flags), BPF_CORE_READ(rq, start_time_ns));
}

static __always_inline void blk_raw_tp_issue(const struct request *const rq) {
    const u64 key = (u64)rq;
    const u32 dev = blk_rq_dev(rq);
    const enum blk_req_kind kind = blk_rq_kind(BPF_CORE_READ(rq, cmd_flags));
    blk_on_issue(&blk_rq_inflight,
                 &key,
                 dev,
                 blk_rq_part_dev(rq, dev),
                 blk_raw_tp_start(rq),
                 kind,
                 blk_want_cgid(kind) ? blk_bio_cgid(BPF_CORE_READ(rq, bio)) : 0);
}

SEC("raw_tp/block_rq_issue")
int obi_stats_raw_tp_block_rq_issue(struct bpf_raw_tracepoint_args *ctx) {
    blk_raw_tp_issue((const struct request *)ctx->args[0]);
    return 0;
}

SEC("raw_tp/block_rq_issue")
int obi_stats_raw_tp_block_rq_issue_legacy(struct bpf_raw_tracepoint_args *ctx) {
    blk_raw_tp_issue((const struct request *)ctx->args[1]);
    return 0;
}

SEC("raw_tp/block_rq_complete")
int obi_stats_raw_tp_block_rq_complete(struct bpf_raw_tracepoint_args *ctx) {
    const struct request *const rq = (const struct request *)ctx->args[0];
    blk_rq_complete((u64)rq, BPF_CORE_READ(rq, __data_len), ctx->args[1], (u32)ctx->args[2]);
    return 0;
}

// Classic tracepoints.

// The classic tracepoint names a request only by (dev, sector), and a flush
// has no sector (the tracepoint reports 0), so every flush on a disk has the
// same key (dev, 0), which a request at sector 0 shares too: while one is in
// flight, the issue of another replaces its entry and the first completion
// ends it, so concurrent flushes on one disk are recorded as one, timed from
// the later issue. The raw tracepoint keys by request and has no such
// collision.
SEC("tracepoint/block/block_rq_issue")
int obi_stats_tp_block_rq_issue(struct trace_event_raw_block_rq *ctx) {
    struct blk_rq_key key = {};
    key.dev = BPF_CORE_READ(ctx, dev);
    key.sector = BPF_CORE_READ(ctx, sector);

    // The classic tracepoint carries no request pointer, so there is no bio
    // or rq->part to read: every event it reports names the whole disk, and
    // no cgroup.
    blk_on_issue(&blk_rq_inflight_sector,
                 &key,
                 key.dev,
                 0,
                 0, // the classic tracepoint carries no request: no start time, no queue time
                 blk_kind_from_rwbs(BPF_CORE_READ(ctx, rwbs[0]), BPF_CORE_READ(ctx, rwbs[1])),
                 0);
    return 0;
}

// The classic tracepoint reports neither the request nor what is left of it,
// so every completion it matches ends its request. Its error field is an
// errno on every kernel.
SEC("tracepoint/block/block_rq_complete")
int obi_stats_tp_block_rq_complete(void *ctx) {
    struct blk_rq_key key = {};
    u32 nr_sector = 0;
    int error = 0;

    if (bpf_core_type_exists(struct trace_event_raw_block_rq_completion___x)) {
        struct trace_event_raw_block_rq_completion___x *const c = ctx;
        key.dev = BPF_CORE_READ(c, dev);
        key.sector = BPF_CORE_READ(c, sector);
        nr_sector = BPF_CORE_READ(c, nr_sector);
        error = BPF_CORE_READ(c, error);
    } else {
        struct trace_event_raw_block_rq_complete *const c = ctx;
        key.dev = BPF_CORE_READ(c, dev);
        key.sector = BPF_CORE_READ(c, sector);
        nr_sector = BPF_CORE_READ(c, nr_sector);
        error = BPF_CORE_READ(c, error);
    }

    blk_on_complete(&blk_rq_inflight_sector, &key, nr_sector * k_blk_bytes_per_sector, true, error);
    return 0;
}
