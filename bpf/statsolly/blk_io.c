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

enum { k_blk_bytes_per_sector = 512 };

// rwbs[0] == 'W' (write) or 'F' (flush) means write; anything else is a read.
static __always_inline u8 blk_op_from_rwbs(const unsigned char rwbs[8]) {
    return (rwbs[0] == 'W' || rwbs[0] == 'F') ? 1 : 0;
}

SEC("tracepoint/block/block_rq_issue")
int obi_stats_tp_block_rq_issue(struct trace_event_raw_block_rq *ctx) {
    struct blk_rq_key key = {};
    key.dev = BPF_CORE_READ(ctx, dev);
    key.sector = BPF_CORE_READ(ctx, sector);

    const u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&blk_start, &key, &now, BPF_ANY);
    return 0;
}

SEC("tracepoint/block/block_rq_complete")
int obi_stats_tp_block_rq_complete(struct trace_event_raw_block_rq_complete *ctx) {
    struct blk_rq_key key = {};
    key.dev = BPF_CORE_READ(ctx, dev);
    key.sector = BPF_CORE_READ(ctx, sector);

    const u64 *issue_ns = bpf_map_lookup_elem(&blk_start, &key);
    if (!issue_ns) {
        return 0; // no matching issue seen; skip
    }
    const u64 latency = bpf_ktime_get_ns() - *issue_ns;
    bpf_map_delete_elem(&blk_start, &key);

    const u32 nr_sector = BPF_CORE_READ(ctx, nr_sector);
    unsigned char rwbs[8];
    bpf_probe_read_kernel(&rwbs, sizeof(rwbs), &ctx->rwbs);

    block_io_t *e = bpf_ringbuf_reserve(&stats_events, sizeof(*e), 0);
    if (!e) {
        bpf_d_printk("block_io: stats_events ring buffer full, dropping event");
        return 0;
    }
    e->flags = k_event_stat_block_io;
    e->op = blk_op_from_rwbs(rwbs);
    e->_pad[0] = 0;
    e->_pad[1] = 0;
    e->dev = key.dev;
    e->latency_ns = latency;
    e->bytes = (u64)nr_sector * k_blk_bytes_per_sector;
    bpf_ringbuf_submit(e, stats_events_flags());
    return 0;
}
