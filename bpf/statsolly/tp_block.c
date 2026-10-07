// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_builtins.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>
#include <bpfcore/bpf_core_read.h>

#include <logger/bpf_dbg.h>

#include <statsolly/types.h>
#include <statsolly/maps/stats_events.h>
#include <statsolly/maps/block_rq_start.h>
#include <statsolly/maps/disk_io_accum.h>

// block_rq_issue passed (struct request_queue *q, struct request *rq) before
// Linux 5.11 and only rq since. Userspace inspects the kernel BTF and injects
// the index of the rq argument.
volatile const u32 g_block_rq_issue_rq_arg_idx = 0;

enum {
    k_block_rq_issue_max_args = 2,
    k_ns_per_us = 1000,
    // include/linux/blk_types.h: REQ_OP_BITS and REQ_OP_MASK
    k_req_op_bits = 8,
    k_req_op_mask = (1U << k_req_op_bits) - 1,
    // include/linux/kdev_t.h: MINORBITS
    k_minorbits = 20,
    // Flush a partially filled batch once its oldest sample is this old.
    k_disk_io_flush_ns = 1000000000ULL,
};

typedef struct disk_io {
    u8 flags; // Must be first, we use it to tell what kind of event we have on the ring buffer
    enum disk_io_direction direction;
    u8 count;
    u8 _pad[1];
    u32 dev;
    u32 latency_us[k_disk_io_batch_size];
} disk_io_t;

// Force structs into the ELF for automatic creation of Golang struct
const disk_io_t *unused_disk_io __attribute__((unused));

static __always_inline struct gendisk *request_disk(struct request *rq) {
    if (bpf_core_field_exists(rq->rq_disk)) {
        return BPF_CORE_READ(rq, rq_disk);
    }
    return BPF_CORE_READ(rq, q, disk);
}

static __always_inline u32 request_dev(struct request *rq) {
    struct gendisk *disk = request_disk(rq);
    if (!disk) {
        return 0;
    }
    const u32 major = BPF_CORE_READ(disk, major);
    const u32 minor = BPF_CORE_READ(disk, first_minor);
    return (major << k_minorbits) | minor;
}

static __always_inline enum disk_io_direction request_direction(struct request *rq) {
    const u32 op = BPF_CORE_READ(rq, cmd_flags) & k_req_op_mask;
    switch (op) {
    case REQ_OP_READ:
        return disk_io_read;
    case REQ_OP_WRITE:
        return disk_io_write;
    default:
        return disk_io_other;
    }
}

static __always_inline void flush_disk_io_accum(const disk_io_accum_key_t *key,
                                                const disk_io_accum_t *accum) {
    disk_io_t *se = bpf_ringbuf_reserve(&stats_events, sizeof(*se), 0);
    if (!se) {
        bpf_d_printk("disk_io_accum: stats_events ring buffer full, dropping batch");
        return;
    }
    se->flags = k_stat_type_disk_io;
    se->direction = key->direction;
    se->count = accum->count;
    se->dev = key->dev;
    bpf_memcpy(se->latency_us, accum->latency_us, sizeof(se->latency_us));
    bpf_ringbuf_submit(se, stats_events_flags());
}

static __always_inline void
accumulate_disk_io(u32 dev, enum disk_io_direction direction, u64 now_ns, u32 latency_us) {
    const disk_io_accum_key_t key = {.dev = dev, .direction = direction};
    disk_io_accum_t *accum = bpf_map_lookup_elem(&disk_io_accum, &key);
    if (!accum) {
        disk_io_accum_t new_accum = {};
        new_accum.first_ns = now_ns;
        new_accum.latency_us[0] = latency_us;
        new_accum.count = 1;
        if (bpf_map_update_elem(&disk_io_accum, &key, &new_accum, BPF_NOEXIST) != 0) {
            bpf_d_printk("disk_io_accum map full, dropping sample");
        }
        return;
    }

    if (now_ns - accum->first_ns > k_disk_io_flush_ns) {
        flush_disk_io_accum(&key, accum);
        accum->count = 0;
        accum->first_ns = now_ns;
    }

    const u8 idx = accum->count;
    if (idx < k_disk_io_batch_size) {
        accum->latency_us[idx] = latency_us;
        accum->count = idx + 1;
    }
    if (accum->count >= k_disk_io_batch_size) {
        flush_disk_io_accum(&key, accum);
        bpf_map_delete_elem(&disk_io_accum, &key);
    }
}

SEC("raw_tracepoint/block_rq_issue")
int obi_stats_raw_tp_block_rq_issue(struct bpf_raw_tracepoint_args *ctx) {
    const u32 idx = g_block_rq_issue_rq_arg_idx;
    if (idx >= k_block_rq_issue_max_args) {
        return 0;
    }
    const u64 rq = ctx->args[idx];
    const u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&block_rq_start, &rq, &now, BPF_ANY);
    return 0;
}

SEC("raw_tracepoint/block_rq_complete")
int obi_stats_raw_tp_block_rq_complete(struct bpf_raw_tracepoint_args *ctx) {
    const u64 rq_key = ctx->args[0];
    const u64 *start = bpf_map_lookup_elem(&block_rq_start, &rq_key);
    if (!start) {
        return 0;
    }
    const u64 now = bpf_ktime_get_ns();
    const u64 issued = *start;
    bpf_map_delete_elem(&block_rq_start, &rq_key);
    if (now < issued) {
        return 0;
    }

    struct request *const rq = (struct request *)rq_key;
    const enum disk_io_direction direction = request_direction(rq);
    if (direction == disk_io_other) {
        return 0;
    }

    const u64 latency_us = (now - issued) / k_ns_per_us;
    accumulate_disk_io(request_dev(rq), direction, now, (u32)latency_us);
    return 0;
}
