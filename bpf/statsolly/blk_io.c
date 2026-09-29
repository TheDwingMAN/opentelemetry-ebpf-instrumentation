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

// Discards ('D') and secure erases ('N') are dropped in
// obi_stats_tp_block_rq_complete before reaching this function.
enum { k_rwbs_discard = 'D', k_rwbs_none = 'N' };

// rwbs[0] == 'W' (write) or 'F' (flush) means write; anything else is a read.
static __always_inline enum blk_io_op blk_op_from_rwbs0(const char rwbs0) {
    return (rwbs0 == 'W' || rwbs0 == 'F') ? blk_op_write : blk_op_read;
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

SEC("tracepoint/block/block_rq_insert")
int obi_stats_tp_block_rq_insert(struct trace_event_raw_block_rq *ctx) {
    struct blk_rq_key key = {};
    key.dev = BPF_CORE_READ(ctx, dev);
    key.sector = BPF_CORE_READ(ctx, sector);

    const u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&blk_insert, &key, &now, BPF_ANY);
    return 0;
}

SEC("tracepoint/block/block_rq_issue")
int obi_stats_tp_block_rq_issue(struct trace_event_raw_block_rq *ctx) {
    struct blk_rq_key key = {};
    key.dev = BPF_CORE_READ(ctx, dev);
    key.sector = BPF_CORE_READ(ctx, sector);

    const u64 now = bpf_ktime_get_ns();

    // A re-issue (requeued request already in blk_start) must not increment
    // inflight again -- it was already counted on the first issue -- so only
    // refresh its timestamp. Pairs with the unconditional decrement in
    // obi_stats_tp_block_rq_complete.
    if (bpf_map_update_elem(&blk_start, &key, &now, BPF_NOEXIST) == 0) {
        blk_dev_state_on_issue(key.dev);
    } else {
        bpf_map_update_elem(&blk_start, &key, &now, BPF_ANY);
    }
    return 0;
}

SEC("tracepoint/block/block_rq_complete")
int obi_stats_tp_block_rq_complete(void *ctx) {
    struct blk_rq_key key = {};
    u32 nr_sector = 0;
    char rwbs0 = 0;
    int error = 0;

    if (bpf_core_type_exists(struct trace_event_raw_block_rq_completion___x)) {
        struct trace_event_raw_block_rq_completion___x *const c = ctx;
        key.dev = BPF_CORE_READ(c, dev);
        key.sector = BPF_CORE_READ(c, sector);
        nr_sector = BPF_CORE_READ(c, nr_sector);
        rwbs0 = BPF_CORE_READ(c, rwbs[0]);
        error = BPF_CORE_READ(c, error);
    } else {
        struct trace_event_raw_block_rq_complete *const c = ctx;
        key.dev = BPF_CORE_READ(c, dev);
        key.sector = BPF_CORE_READ(c, sector);
        nr_sector = BPF_CORE_READ(c, nr_sector);
        rwbs0 = BPF_CORE_READ(c, rwbs[0]);
        error = BPF_CORE_READ(c, error);
    }

    const u64 now = bpf_ktime_get_ns();

    // Every completion decrements inflight, matched or not: an unmatched
    // completion (blk_start entry evicted or the request predates this
    // program attaching) still corresponds to a request that was counted at
    // issue. The clamp-at-zero in blk_dev_state_on_complete protects the
    // latter case.
    const u64 inflight = blk_dev_state_on_complete(key.dev);

    const u64 *issue_ns = bpf_map_lookup_elem(&blk_start, &key);
    if (!issue_ns) {
        return 0;
    }
    const u64 latency = now - *issue_ns;

    u64 queue_ns = 0;
    const u64 *insert_ns = bpf_map_lookup_elem(&blk_insert, &key);
    if (insert_ns) {
        queue_ns = *issue_ns - *insert_ns;
        bpf_map_delete_elem(&blk_insert, &key);
    }
    bpf_map_delete_elem(&blk_start, &key);

    // Discards and secure erases are not read/write throughput; drop them
    // rather than folding them into the read counters.
    if (rwbs0 == k_rwbs_discard || rwbs0 == k_rwbs_none) {
        return 0;
    }

    block_io_t *const se = bpf_ringbuf_reserve(&stats_events, sizeof(*se), 0);
    if (!se) {
        bpf_d_printk("block_io: stats_events ring buffer full, dropping event");
        return 0;
    }
    se->flags = k_event_stat_block_io;
    se->op = blk_op_from_rwbs0(rwbs0);
    se->_pad[0] = 0;
    se->_pad[1] = 0;
    se->dev = key.dev;
    se->latency_ns = latency;
    se->queue_ns = queue_ns;
    se->bytes = (u64)nr_sector * k_blk_bytes_per_sector;
    se->error = error;
    se->inflight = (u32)inflight;
    bpf_ringbuf_submit(se, stats_events_flags());
    return 0;
}
