// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_core_read.h>

#include <logger/bpf_dbg.h>

#include <statsolly/types.h>
#include <statsolly/blk_helpers.h>
#include <statsolly/maps/stats_events.h>
#include <statsolly/maps/blk_dev_state.h>
#include <statsolly/maps/blk_agg.h>
#include <statsolly/maps/blk_cg_agg.h>
#include <statsolly/maps/stats_drops.h>
#include <statsolly/hist.h>

#include <common/scratch_mem.h>

// What the block request programs (blk_io.c) and the bio programs of stacked
// volumes (blk_bio.c) share: an operation enters an in-flight map when it is
// issued (a request) or queued (a bio), and leaves it at its completion, which
// is then counted in the aggregation maps or sent as a ring buffer event. The
// two are objects of their own, loaded as separate collections; the maps here
// are PinInternal, so both count in the same ones, and the constants get the
// same values in both (statsConstants).

// Set by userspace when the deprecated obi.stat.disk.queue.depth metric is
// enabled. When 0 the per-device in-flight counter, the only shared
// read-modify-write on the block path, is dead code to the verifier.
volatile const u8 blk_want_queue_depth;

// Set by userspace when obi.disk.partition is selected on a disk metric
// (attributes.select), rather than by its own feature flag: the partition is
// read at issue and carried in the in-flight value and the aggregation key,
// never in the key unconditionally (a full map must not drop node-level
// data because of a dimension nobody asked for). When 0 the reads it gates
// are dead code to the verifier, so a node-level-only deployment pays nothing.
volatile const u8 blk_want_part;

// Set by userspace when storage_block_pod is on (and the host has cgroup v2
// with the io controller): the issue of a read or write, or the queueing of
// a bio, reads the cgroup it is charged to (blk_cgroup.h), and its completion
// is counted in blk_cg_agg, whatever the emit mode. When 0 those reads and
// the map update are dead code to the verifier.
volatile const u8 blk_want_cgroup;

// The kinds of request whose completions reach userspace, one bit per enum
// blk_req_kind, set by userspace from the enabled metrics. The others end at
// their completion, after their in-flight entry is released, without a ring
// buffer event.
volatile const u8 blk_emit_kinds;

// How completions reach userspace: enum blk_emit, set by userspace. In
// AGG mode they are counted in the blk_agg maps and the ring buffer carries no
// block event.
volatile const u8 blk_emit_mode;

// AGG mode: set when the histograms use the exponential layout, whose bounds
// are blk_exp_bounds_ns, rather than the explicit one, blk_bounds_ns. Both are
// in nanoseconds, sorted, padded with U64_MAX (bpf/statsolly/hist.h).
volatile const u8 blk_hist_exp;
volatile const u64 blk_bounds_ns[k_stat_hist_max_bounds];
volatile const u64 blk_exp_bounds_ns[k_stat_hist_exp_max_bounds];

// A new aggregation key starts from this zeroed value, never written. The
// exponential value is the largest one inserted.
SCRATCH_MEM_TYPED(blk_agg_zero, struct blk_agg_exp_val)
_Static_assert(sizeof(struct blk_agg_exp_val) >= sizeof(struct blk_cg_val),
               "blk_agg_zero must cover every aggregation value");

// A request's kind is sent to userspace as the event's op.
_Static_assert((int)blk_req_read == (int)blk_op_read && (int)blk_req_write == (int)blk_op_write &&
                   (int)blk_req_flush == (int)blk_op_flush &&
                   (int)blk_req_discard == (int)blk_op_discard,
               "enum blk_req_kind must match enum blk_io_op");

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

// blk_inflight_begin records an operation that starts now: a request at its
// issue, keyed by request pointer or (dev, sector), or a bio at its queueing,
// keyed by bio pointer. full is the drop counted when the map has no room.
//
// The key may already have an entry. For a request (is_bio false) that is a
// requeue, or a request struct reused after a completion this program missed
// (blk_rq_reissue). A bio is queued once, so an entry under its pointer is
// always the leftover of a bio whose completion was missed, in a struct the
// kernel has since reused (blk_bio_requeue). Neither is a new operation in
// flight, so the queue depth does not change, unless the reused struct moved
// the entry to another disk (request structs come from a tag set that several
// disks share, bios from a pool every device shares). Its count then moves
// too, so the stale issue does not hold the old disk up forever and the final
// completion does not take the new one below zero.
static __always_inline void blk_inflight_begin(void *const inflight_map,
                                               const void *const key,
                                               const struct blk_rq_inflight *const issued,
                                               const bool is_bio,
                                               const enum stats_drop full) {
    if (bpf_map_update_elem(inflight_map, key, issued, BPF_NOEXIST) == 0) {
        blk_queue_depth_inc(issued->dev);
        return;
    }

    struct blk_rq_inflight *const cur = bpf_map_lookup_elem(inflight_map, key);
    if (!cur) {
        // Not an entry of its own: the map is full.
        stats_count_drop(full);
        return;
    }
    const u32 prev_dev = is_bio ? blk_bio_requeue(cur, issued) : blk_rq_reissue(cur, issued);
    if (prev_dev != issued->dev) {
        blk_queue_depth_dec(prev_dev);
        blk_queue_depth_inc(issued->dev);
    }
}

// blk_agg_lookup_or_init returns key's value in map, inserting a zeroed one
// first when the key is new. A full map fails the insert: the completion is
// not counted, and the drop is.
static __always_inline void *
blk_agg_lookup_or_init(void *const map, const void *const key, const enum stats_drop reason) {
    void *value = bpf_map_lookup_elem(map, key);
    if (value) {
        return value;
    }

    const void *const zero = blk_agg_zero_mem();
    if (!zero) {
        return NULL;
    }
    // Another program may insert the key between the lookup and here, and
    // NOEXIST then fails harmlessly: the second lookup finds its value.
    bpf_map_update_elem(map, key, zero, BPF_NOEXIST);
    value = bpf_map_lookup_elem(map, key);
    if (!value) {
        stats_count_drop(reason);
    }
    return value;
}

// Different programs (issue and completion, block and filesystem) share a
// CPU's values and can interrupt each other, so the per-CPU words are added to
// atomically.
static __always_inline void blk_agg_add(u64 *const word, const u64 n) {
    if (n) {
        __sync_fetch_and_add(word, n);
    }
}

static __always_inline void
blk_agg_service(const struct blk_agg_key *const key, const u64 bytes, const u64 svc_ns) {
    if (blk_hist_exp) {
        struct blk_agg_exp_val *const v =
            blk_agg_lookup_or_init(&blk_agg_exp, key, k_stats_drop_blk_agg);
        if (!v) {
            return;
        }
        blk_agg_add(&v->bytes, bytes);
        blk_agg_add(&v->svc_sum_ns, svc_ns);
        stat_hist_exp_add(v->svc_bkt, stat_hist_exp_idx(blk_exp_bounds_ns, svc_ns));
        return;
    }

    struct blk_agg_val *const v = blk_agg_lookup_or_init(&blk_agg, key, k_stats_drop_blk_agg);
    if (!v) {
        return;
    }
    blk_agg_add(&v->bytes, bytes);
    blk_agg_add(&v->svc_sum_ns, svc_ns);
    stat_hist_add(v->svc_bkt, stat_hist_idx(blk_bounds_ns, svc_ns));
}

// blk_cg_count counts a completed read or write for the cgroup it was charged
// to, in blk_cg_agg (storage_block_pod). It runs for every completion that
// ends an operation, whatever its kind is emitted: the pod counters are
// their own metrics, and with no other block metric enabled nothing else
// is.
static __always_inline void
blk_cg_count(const struct blk_rq_inflight *const op, const u64 bytes, const u64 svc_ns) {
    if (!blk_want_cgroup || !blk_kind_is_read_write(op->kind)) {
        return;
    }
    const struct blk_cg_key key = blk_cg_key_of(op);
    struct blk_cg_val *const v = blk_agg_lookup_or_init(&blk_cg_agg, &key, k_stats_drop_blk_cg_agg);
    if (!v) {
        return;
    }
    __sync_fetch_and_add(&v->count, 1);
    blk_agg_add(&v->bytes, bytes);
    blk_agg_add(&v->time_ns, blk_op_time_ns(svc_ns, op->queue_ns));
}

// A completed operation, as blk_inflight_end hands it over to be counted.
struct blk_done {
    struct blk_rq_inflight op;
    u64 bytes;
    u64 svc_ns;   // issue (or bio queueing) -> completion
    u32 inflight; // operations still in flight on the device, for queue.depth
    u32 _pad;
};

// blk_inflight_end handles a completion of key: nr_bytes more of it are done,
// and final says whether that ends it. It returns true, with done filled in,
// only when the operation ended and userspace wants its kind; a completion
// that is to have no effect returns false. An operation that ended is counted
// in the pod counters either way (blk_cg_count).
static __always_inline bool blk_inflight_end(void *const inflight_map,
                                             const void *const key,
                                             const u32 nr_bytes,
                                             const bool final,
                                             struct blk_done *const done) {
    struct blk_rq_inflight *const cur = bpf_map_lookup_elem(inflight_map, key);
    if (!cur) {
        // Issued before this program attached, or already ended. On a device
        // without FUA, a write in a flush sequence (PREFLUSH or FUA) completes
        // twice: with its bytes, which ends it here, then with none once the
        // flush machinery's post-flush is done. The flushes themselves are
        // requests of their own. For bios: a bio of a device that is not
        // tracked, or a fragment a driver split off a tracked bio, which
        // completes under a pointer that was never queued.
        return false;
    }

    if (!final) {
        cur->bytes_done += nr_bytes;
        return false;
    }

    const u64 now = bpf_ktime_get_ns();

    // Copy before deleting: a deleted element can be handed to another CPU.
    done->op = *cur;
    if (bpf_map_delete_elem(inflight_map, key) != 0) {
        // Another completion with the same classic (dev, sector) key won.
        return false;
    }
    done->inflight = blk_queue_depth_dec(done->op.dev);
    done->_pad = 0;
    done->bytes = done->op.bytes_done + nr_bytes;
    done->svc_ns = now - done->op.issue_ns;

    blk_cg_count(&done->op, done->bytes, done->svc_ns);
    return blk_kind_emitted(blk_emit_kinds, done->op.kind);
}

// blk_emit_event sends a completed operation to userspace as a ring buffer
// event, in the RINGBUF emit mode.
static __always_inline void blk_emit_event(const struct blk_done *const done, const int error) {
    block_io_t *const se = bpf_ringbuf_reserve(&stats_events, sizeof(*se), 0);
    if (!se) {
        bpf_d_printk("block_io: stats_events ring buffer full, dropping event");
        return;
    }
    se->flags = k_stat_type_block_io;
    se->op = (enum blk_io_op)done->op.kind;
    se->_pad[0] = 0;
    se->_pad[1] = 0;
    se->dev = done->op.dev;
    se->latency_ns = done->svc_ns;
    se->queue_ns = done->op.queue_ns;
    se->bytes = done->bytes;
    se->error = error;
    se->inflight = done->inflight;
    se->part_dev = done->op.part_dev;
    __builtin_memset(se->_pad2, 0, sizeof(se->_pad2));
    bpf_ringbuf_submit(se, stats_events_flags());
}
