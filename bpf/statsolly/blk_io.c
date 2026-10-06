// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_core_read.h>

#include <logger/bpf_dbg.h>

#include <statsolly/types.h>
#include <statsolly/maps/stats_events.h>
#include <statsolly/maps/blk_start.h>
#include <statsolly/maps/blk_dev_state.h>

enum { k_blk_bytes_per_sector = 512 };

// Newer kernels renamed the completion tracepoint context struct
// (trace_event_raw_block_rq_complete -> ..._completion) and grew rwbs[8]
// to rwbs[10]. CO-RE flavor: only the fields we access; ___x is ignored
// in BTF name matching.
// Field order chosen (dev, nr_sector, sector, rwbs, explicit pad, error)
// so no implicit padding is inserted: -Wpadded is enabled build-wide, and
// CO-RE relocates by field name, not struct layout, so reordering here is
// safe.
struct trace_event_raw_block_rq_completion___x {
    dev_t dev;
    unsigned int nr_sector;
    sector_t sector;
    char rwbs[10];
    unsigned char _pad[2];
    int error;
} __attribute__((preserve_access_index));

// Self-evicting scratch map for in-flight request queue-wait timing
// (insert -> issue): entries whose issue never arrives (merges, requeues,
// splits, error paths) would otherwise orphan and fill a plain HASH;
// LRU_HASH evicts the least-recently-used entry instead of failing writes
// once full. Same key shape as blk_start.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1 << 16);
    __type(key, struct blk_rq_key);
    __type(value, u64); // insert timestamp (ns)
    __uint(pinning, OBI_PIN_INTERNAL);
} blk_insert SEC(".maps");

// What a completed request was, as far as the metrics care: a read, a write,
// or something that is neither (discards and secure erases are not
// throughput and are dropped rather than folded into the read counters).
enum blk_req_kind : u8 {
    blk_req_read = 0,
    blk_req_write = 1,
    blk_req_ignore = 2,
};

// The classic tracepoint hands over the rwbs string: 'W' (write) or 'F'
// (flush) means write, 'D' (discard) and 'N' (secure erase) are ignored,
// anything else is a read.
static __always_inline enum blk_req_kind blk_kind_from_rwbs0(const char rwbs0) {
    if (rwbs0 == 'W' || rwbs0 == 'F') {
        return blk_req_write;
    }
    if (rwbs0 == 'D' || rwbs0 == 'N') {
        return blk_req_ignore;
    }
    return blk_req_read;
}

// The raw tracepoint hands over the request itself, whose operation lives in
// the low bits of cmd_flags. Values are the kernel's REQ_OP_* ABI, which is
// not in BTF because they are macros.
enum { k_sector_shift = 9 }; // 512-byte sectors, as the tracepoint reports them

enum {
    k_req_op_mask = 0xff,
    k_req_op_read = 0,
    k_req_op_write = 1,
    k_req_op_flush = 2,
    k_req_op_discard = 3,
    k_req_op_secure_erase = 5,
    k_req_op_write_zeroes = 9,
};

static __always_inline enum blk_req_kind blk_kind_from_cmd_flags(const u32 cmd_flags) {
    switch (cmd_flags & k_req_op_mask) {
    case k_req_op_read:
        return blk_req_read;
    case k_req_op_write:
    case k_req_op_flush:
    case k_req_op_write_zeroes:
        return blk_req_write;
    default:
        return blk_req_ignore;
    }
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

static __always_inline struct blk_dev_state *blk_dev_state_get(const u32 dev) {
    struct blk_dev_state *const existing = bpf_map_lookup_elem(&blk_dev_state, &dev);
    if (existing) {
        return existing;
    }

    const struct blk_dev_state empty = {};
    bpf_map_update_elem(&blk_dev_state, &dev, &empty, BPF_NOEXIST);
    return bpf_map_lookup_elem(&blk_dev_state, &dev);
}

static __always_inline void blk_dev_state_on_issue(const u32 dev) {
    struct blk_dev_state *const st = blk_dev_state_get(dev);
    if (!st) {
        return;
    }

    st->inflight++;
}

// Returns the inflight count remaining on dev after this completion, for the
// ring buffer event.
static __always_inline u64 blk_dev_state_on_complete(const u32 dev) {
    struct blk_dev_state *const st = blk_dev_state_get(dev);
    if (!st) {
        return 0;
    }

    // A request already in flight when this program attached has no matching
    // issue increment, so decrementing for its completion would underflow the
    // counter.
    if (st->inflight == 0) {
        return 0;
    }

    st->inflight--;
    return st->inflight;
}

static __always_inline void blk_on_insert(const u32 dev, const u64 sector) {
    struct blk_rq_key key = {};
    key.dev = dev;
    key.sector = sector;

    const u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&blk_insert, &key, &now, BPF_ANY);
}

static __always_inline void blk_on_issue(const u32 dev, const u64 sector) {
    struct blk_rq_key key = {};
    key.dev = dev;
    key.sector = sector;

    const u64 now = bpf_ktime_get_ns();

    // A re-issue (requeued request already in blk_start) must not increment
    // inflight again -- it was already counted on the first issue -- so only
    // refresh its timestamp. Pairs with the unconditional decrement in
    // blk_on_complete.
    if (bpf_map_update_elem(&blk_start, &key, &now, BPF_NOEXIST) == 0) {
        blk_dev_state_on_issue(key.dev);
    } else {
        bpf_map_update_elem(&blk_start, &key, &now, BPF_ANY);
    }
}

// The raw tracepoint's first argument is the request itself. Its device is
// taken the way the classic tracepoint takes it, from the request's gendisk
// (disk_devt: MKDEV(major, first_minor)), so both attach modes name the whole
// disk rather than the partition, and a flush request, which has no
// partition, still names its disk. Kernels before 5.15 keep the gendisk on the
// request (rq_disk); since 5.15, and on RHEL 9 which backports it, it lives on
// the queue. Which one exists is decided at load time by CO-RE, and the
// untaken branch is dead code to the verifier.
enum { k_minorbits = 20 }; // MINORBITS: dev_t is major << 20 | minor

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
    return ((u32)BPF_CORE_READ(disk, major) << k_minorbits) | (u32)BPF_CORE_READ(disk, first_minor);
}

SEC("tracepoint/block/block_rq_insert")
int obi_stats_tp_block_rq_insert(struct trace_event_raw_block_rq *ctx) {
    blk_on_insert(BPF_CORE_READ(ctx, dev), BPF_CORE_READ(ctx, sector));
    return 0;
}

SEC("raw_tp/block_rq_insert")
int obi_stats_raw_tp_block_rq_insert(struct bpf_raw_tracepoint_args *ctx) {
    const struct request *const rq = (const struct request *)ctx->args[0];
    blk_on_insert(blk_rq_dev(rq), BPF_CORE_READ(rq, __sector));
    return 0;
}

SEC("tracepoint/block/block_rq_issue")
int obi_stats_tp_block_rq_issue(struct trace_event_raw_block_rq *ctx) {
    blk_on_issue(BPF_CORE_READ(ctx, dev), BPF_CORE_READ(ctx, sector));
    return 0;
}

SEC("raw_tp/block_rq_issue")
int obi_stats_raw_tp_block_rq_issue(struct bpf_raw_tracepoint_args *ctx) {
    const struct request *const rq = (const struct request *)ctx->args[0];
    blk_on_issue(blk_rq_dev(rq), BPF_CORE_READ(rq, __sector));
    return 0;
}

static __always_inline void blk_on_complete(const u32 dev,
                                            const u64 sector,
                                            const u32 nr_sector,
                                            const enum blk_req_kind kind,
                                            const int error) {
    struct blk_rq_key key = {};
    key.dev = dev;
    key.sector = sector;

    const u64 now = bpf_ktime_get_ns();

    // Every completion decrements inflight, matched or not: an unmatched
    // completion (blk_start entry evicted or the request predates this
    // program attaching) still corresponds to a request that was counted at
    // issue. The clamp-at-zero in blk_dev_state_on_complete protects the
    // latter case.
    const u64 inflight = blk_dev_state_on_complete(key.dev);

    const u64 *issue_ns = bpf_map_lookup_elem(&blk_start, &key);
    if (!issue_ns) {
        return;
    }
    const u64 latency = now - *issue_ns;

    u64 queue_ns = 0;
    const u64 *insert_ns = bpf_map_lookup_elem(&blk_insert, &key);
    if (insert_ns) {
        queue_ns = *issue_ns - *insert_ns;
        bpf_map_delete_elem(&blk_insert, &key);
    }
    bpf_map_delete_elem(&blk_start, &key);

    if (kind == blk_req_ignore) {
        return;
    }

    block_io_t *const se = bpf_ringbuf_reserve(&stats_events, sizeof(*se), 0);
    if (!se) {
        bpf_d_printk("block_io: stats_events ring buffer full, dropping event");
        return;
    }
    se->flags = k_stat_type_block_io;
    se->op = kind == blk_req_write ? blk_op_write : blk_op_read;
    se->_pad[0] = 0;
    se->_pad[1] = 0;
    se->dev = key.dev;
    se->latency_ns = latency;
    se->queue_ns = queue_ns;
    se->bytes = (u64)nr_sector * k_blk_bytes_per_sector;
    se->error = error;
    se->inflight = (u32)inflight;
    bpf_ringbuf_submit(se, stats_events_flags());
}

SEC("tracepoint/block/block_rq_complete")
int obi_stats_tp_block_rq_complete(void *ctx) {
    u32 dev = 0;
    u64 sector = 0;
    u32 nr_sector = 0;
    char rwbs0 = 0;
    int error = 0;

    if (bpf_core_type_exists(struct trace_event_raw_block_rq_completion___x)) {
        struct trace_event_raw_block_rq_completion___x *const c = ctx;
        dev = BPF_CORE_READ(c, dev);
        sector = BPF_CORE_READ(c, sector);
        nr_sector = BPF_CORE_READ(c, nr_sector);
        rwbs0 = BPF_CORE_READ(c, rwbs[0]);
        error = BPF_CORE_READ(c, error);
    } else {
        struct trace_event_raw_block_rq_complete *const c = ctx;
        dev = BPF_CORE_READ(c, dev);
        sector = BPF_CORE_READ(c, sector);
        nr_sector = BPF_CORE_READ(c, nr_sector);
        rwbs0 = BPF_CORE_READ(c, rwbs[0]);
        error = BPF_CORE_READ(c, error);
    }

    blk_on_complete(dev, sector, nr_sector, blk_kind_from_rwbs0(rwbs0), error);
    return 0;
}

// block_rq_complete(struct request *rq, blk_status_t error, unsigned int nr_bytes)
SEC("raw_tp/block_rq_complete")
int obi_stats_raw_tp_block_rq_complete(struct bpf_raw_tracepoint_args *ctx) {
    const struct request *const rq = (const struct request *)ctx->args[0];
    const u8 status = (u8)ctx->args[1];
    const u32 nr_bytes = (u32)ctx->args[2];

    blk_on_complete(blk_rq_dev(rq),
                    BPF_CORE_READ(rq, __sector),
                    nr_bytes >> k_sector_shift,
                    blk_kind_from_cmd_flags(BPF_CORE_READ(rq, cmd_flags)),
                    blk_status_to_errno(status));
    return 0;
}
