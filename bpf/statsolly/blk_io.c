// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_core_read.h>

#include <logger/bpf_dbg.h>

#include <statsolly/types.h>
#include <statsolly/blk_helpers.h>
#include <statsolly/maps/stats_events.h>
#include <statsolly/maps/blk_rq_inflight.h>
#include <statsolly/maps/blk_dev_state.h>

enum { k_blk_bytes_per_sector = 512 };

// Set by userspace when the deprecated obi.stat.disk.queue.depth metric is
// enabled. When 0 the per-device in-flight counter, the only shared
// read-modify-write on the block path, is dead code to the verifier.
volatile const u8 blk_want_queue_depth;

// The kinds of request whose completions reach userspace, one bit per enum
// blk_req_kind, set by userspace from the enabled metrics. The others end here,
// after their in-flight entry is released, without a ring buffer event.
volatile const u8 blk_emit_kinds;

// A request's kind is sent to userspace as the event's op.
_Static_assert((int)blk_req_read == (int)blk_op_read && (int)blk_req_write == (int)blk_op_write &&
                   (int)blk_req_flush == (int)blk_op_flush &&
                   (int)blk_req_discard == (int)blk_op_discard,
               "enum blk_req_kind must match enum blk_io_op");

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

// REQ_OP_* is an enum in BTF: enum req_opf, which bpfcore/vmlinux.h carries,
// renamed enum req_op in Linux 6.0 and on RHEL 9. The zone operations have
// been renumbered along the way, so REQ_OP_ZONE_APPEND is resolved by CO-RE
// from whichever of the two this kernel has.
enum req_op___new {
    REQ_OP_ZONE_APPEND___new = 7,
};

static __always_inline u32 blk_req_op_zone_append(void) {
    if (bpf_core_enum_value_exists(enum req_op___new, REQ_OP_ZONE_APPEND___new)) {
        return bpf_core_enum_value(enum req_op___new, REQ_OP_ZONE_APPEND___new);
    }
    if (bpf_core_enum_value_exists(enum req_opf, REQ_OP_ZONE_APPEND)) {
        return bpf_core_enum_value(enum req_opf, REQ_OP_ZONE_APPEND);
    }
    return k_req_op_absent;
}

// Self-evicting scratch map for in-flight request queue-wait timing
// (insert -> issue): entries whose issue never arrives (merges, requeues,
// splits, error paths) would otherwise orphan and fill a plain HASH;
// LRU_HASH evicts the least-recently-used entry instead of failing writes
// once full.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1 << 16);
    __type(key, struct blk_rq_key);
    __type(value, u64); // insert timestamp (ns)
    __uint(pinning, OBI_PIN_INTERNAL);
} blk_insert SEC(".maps");

static __always_inline struct blk_dev_state *blk_dev_state_get(const u32 dev) {
    struct blk_dev_state *const existing = bpf_map_lookup_elem(&blk_dev_state, &dev);
    if (existing) {
        return existing;
    }

    const struct blk_dev_state empty = {};
    bpf_map_update_elem(&blk_dev_state, &dev, &empty, BPF_NOEXIST);
    return bpf_map_lookup_elem(&blk_dev_state, &dev);
}

// Issue and completion of one request can run on different CPUs, and a
// completion in interrupt context can interrupt an issue on the same CPU, so
// the shared counter is only ever changed atomically.
static __always_inline void blk_queue_depth_inc(const u32 dev) {
    if (!blk_want_queue_depth) {
        return;
    }

    struct blk_dev_state *const st = blk_dev_state_get(dev);
    if (!st) {
        return;
    }
    __sync_fetch_and_add(&st->inflight, 1);
}

// Returns the requests still in flight on dev after this completion, for the
// ring buffer event.
static __always_inline u32 blk_queue_depth_dec(const u32 dev) {
    if (!blk_want_queue_depth) {
        return 0;
    }

    struct blk_dev_state *const st = blk_dev_state_get(dev);
    if (!st) {
        return 0;
    }
    __sync_fetch_and_add(&st->inflight, -1);
    // Decrements pair with increments, but the counter is shared and a pairing
    // this program cannot see (a completion racing an issue on another CPU)
    // must not turn an idle device into 2^32-1 in the histogram.
    const s64 inflight = (s64)st->inflight;
    return inflight > 0 ? (u32)inflight : 0;
}

static __always_inline void blk_on_insert(const u32 dev, const u64 sector) {
    struct blk_rq_key key = {};
    key.dev = dev;
    key.sector = sector;

    const u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&blk_insert, &key, &now, BPF_ANY);
}

// Time since block_rq_insert, taken at issue: the request's start sector
// still names it then, while a partial completion advances it.
static __always_inline u64 blk_queue_wait(const u32 dev, const u64 sector, const u64 issue_ns) {
    struct blk_rq_key key = {};
    key.dev = dev;
    key.sector = sector;

    const u64 *const insert_ns = bpf_map_lookup_elem(&blk_insert, &key);
    if (!insert_ns) {
        return 0;
    }
    const u64 queue_ns = issue_ns - *insert_ns;
    bpf_map_delete_elem(&blk_insert, &key);
    return queue_ns;
}

static __always_inline void blk_on_issue(void *const inflight_map,
                                         const void *const key,
                                         const u32 dev,
                                         const u64 sector,
                                         const enum blk_req_kind kind) {
    struct blk_rq_inflight issued = {};
    issued.issue_ns = bpf_ktime_get_ns();
    issued.queue_ns = blk_queue_wait(dev, sector, issued.issue_ns);
    issued.dev = dev;
    issued.kind = kind;

    if (bpf_map_update_elem(inflight_map, key, &issued, BPF_NOEXIST) == 0) {
        blk_queue_depth_inc(dev);
        return;
    }

    // Issued again while its entry is still present: not a new request in
    // flight, so the queue depth does not change, unless a request struct
    // reused after a missed completion moved the entry to another disk of the
    // same tag set. Its count then moves too, so the stale issue does not hold
    // the old disk up forever and the final completion does not take the new
    // one below zero.
    struct blk_rq_inflight *const cur = bpf_map_lookup_elem(inflight_map, key);
    if (!cur) {
        return;
    }
    const u32 prev_dev = blk_rq_reissue(cur, &issued);
    if (prev_dev != dev) {
        blk_queue_depth_dec(prev_dev);
        blk_queue_depth_inc(dev);
    }
}

static __always_inline void blk_on_complete(void *const inflight_map,
                                            const void *const key,
                                            const u32 nr_bytes,
                                            const bool final,
                                            const int error) {
    struct blk_rq_inflight *const cur = bpf_map_lookup_elem(inflight_map, key);
    if (!cur) {
        // Issued before this program attached, or already ended. On a device
        // without FUA, a write in a flush sequence (PREFLUSH or FUA) completes
        // twice: with its bytes, which ends it here, then with none once the
        // flush machinery's post-flush is done. The flushes themselves are
        // requests of their own.
        return;
    }

    if (!final) {
        cur->bytes_done += nr_bytes;
        return;
    }

    const u64 now = bpf_ktime_get_ns();

    // Copy before deleting: a deleted element can be handed to another CPU.
    const struct blk_rq_inflight rq = *cur;
    if (bpf_map_delete_elem(inflight_map, key) != 0) {
        // Another completion with the same classic (dev, sector) key won.
        return;
    }
    const u32 inflight = blk_queue_depth_dec(rq.dev);

    if (!blk_kind_emitted(blk_emit_kinds, rq.kind)) {
        return;
    }

    block_io_t *const se = bpf_ringbuf_reserve(&stats_events, sizeof(*se), 0);
    if (!se) {
        bpf_d_printk("block_io: stats_events ring buffer full, dropping event");
        return;
    }
    se->flags = k_stat_type_block_io;
    se->op = (enum blk_io_op)rq.kind;
    se->_pad[0] = 0;
    se->_pad[1] = 0;
    se->dev = rq.dev;
    se->latency_ns = now - rq.issue_ns;
    se->queue_ns = rq.queue_ns;
    se->bytes = rq.bytes_done + nr_bytes;
    se->error = error;
    se->inflight = inflight;
    se->part_dev = 0;
    __builtin_memset(se->_pad2, 0, sizeof(se->_pad2));
    bpf_ringbuf_submit(se, stats_events_flags());
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
    struct blk_rq_key key = {};
    key.dev = BPF_CORE_READ(ctx, dev);
    key.sector = BPF_CORE_READ(ctx, sector);

    blk_on_issue(&blk_rq_inflight_sector,
                 &key,
                 key.dev,
                 key.sector,
                 blk_kind_from_rwbs(BPF_CORE_READ(ctx, rwbs[0]), BPF_CORE_READ(ctx, rwbs[1])));
    return 0;
}

// block_rq_issue(struct request *rq)
SEC("raw_tp/block_rq_issue")
int obi_stats_raw_tp_block_rq_issue(struct bpf_raw_tracepoint_args *ctx) {
    const struct request *const rq = (const struct request *)ctx->args[0];
    const u64 key = (u64)rq;

    blk_on_issue(&blk_rq_inflight,
                 &key,
                 blk_rq_dev(rq),
                 BPF_CORE_READ(rq, __sector),
                 blk_kind_from_cmd_flags(BPF_CORE_READ(rq, cmd_flags), blk_req_op_zone_append()));
    return 0;
}

// The classic tracepoint reports neither the request nor what is left of it,
// so every completion it matches ends its request.
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

// block_rq_complete(struct request *rq, blk_status_t error, unsigned int nr_bytes)
SEC("raw_tp/block_rq_complete")
int obi_stats_raw_tp_block_rq_complete(struct bpf_raw_tracepoint_args *ctx) {
    const struct request *const rq = (const struct request *)ctx->args[0];
    const u8 status = (u8)ctx->args[1];
    const u32 nr_bytes = (u32)ctx->args[2];
    const u64 key = (u64)rq;

    blk_on_complete(&blk_rq_inflight,
                    &key,
                    nr_bytes,
                    blk_rq_final_chunk(nr_bytes, BPF_CORE_READ(rq, __data_len), status),
                    blk_status_to_errno(status));
    return 0;
}
