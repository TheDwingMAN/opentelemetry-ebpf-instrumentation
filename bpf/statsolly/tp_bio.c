// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_core_read.h>

#include <statsolly/cgroup_names.h>
#include <statsolly/disk_accum.h>
#include <statsolly/disk_io.h>
#include <statsolly/types.h>
#include <statsolly/maps/disk_bio_accum.h>
#include <statsolly/maps/disk_bio_devices.h>
#include <statsolly/maps/disk_bio_start.h>

// Bio-based stacked devices, such as device mapper (LVM, dm-crypt) and md RAID volumes, pass their
// I/O down to the devices below them as bios, never as requests of their own. Their I/O is
// measured from the bio that is submitted to them until its completion.

// bio fields of kernels before Linux 5.12 (including RHEL 8), which had no bi_bdev
struct bio___old {
    struct gendisk *bi_disk;
} __attribute__((preserve_access_index));

static __always_inline struct gendisk *bio_disk(struct bio *bio) {
    if (bpf_core_field_exists(bio->bi_bdev)) {
        return BPF_CORE_READ(bio, bi_bdev, bd_disk);
    }
    const struct bio___old *old = (const void *)bio;
    return BPF_CORE_READ(old, bi_disk);
}

static __always_inline enum disk_op bio_op(struct bio *bio) {
    const u32 preflush_flag = 1U << bpf_core_enum_value(enum req_flag_bits, __REQ_PREFLUSH);
    return disk_bio_op(
        BPF_CORE_READ(bio, bi_opf), k_op_mask, preflush_flag, BPF_CORE_READ(bio, bi_iter.bi_size));
}

static __always_inline void record_bio_queue(struct bio *bio) {
    struct gendisk *disk = bio_disk(bio);
    const u32 major = BPF_CORE_READ(disk, major);
    const u32 minor = BPF_CORE_READ(disk, first_minor);
    const u32 dev = major << k_kernel_dev_minor_bits | minor;
    if (!bpf_map_lookup_elem(&disk_bio_devices, &dev)) {
        return;
    }
    const enum disk_op op = bio_op(bio);
    if (op == disk_op_unknown) {
        return;
    }
    const u64 key = (u64)(uintptr_t)bio;
    const disk_rq_start_t start = {
        .issued_ns = bpf_ktime_get_ns(),
        .queued_ns = k_disk_queue_unknown,
        .bytes = BPF_CORE_READ(bio, bi_iter.bi_size),
        .major = major,
        .minor = minor,
        .op = op,
    };
    bpf_map_update_elem(&disk_bio_start, &key, &start, BPF_ANY);
}

// block_bio_queue went from (q, bio) to (bio) in Linux 5.11, independently of block_rq_issue
// (5.10.137+ backported only the latter). Userspace loads one of the two programs below after
// checking the tracepoint prototype in the kernel BTF.
SEC("raw_tracepoint/block_bio_queue")
int obi_stats_raw_tp_block_bio_queue(struct bpf_raw_tracepoint_args *ctx) {
    record_bio_queue((struct bio *)ctx->args[0]);
    return 0;
}

SEC("raw_tracepoint/block_bio_queue")
int obi_stats_raw_tp_block_bio_queue_legacy(struct bpf_raw_tracepoint_args *ctx) {
    record_bio_queue((struct bio *)ctx->args[1]);
    return 0;
}

// block_bio_complete is (q, bio) on every supported kernel
SEC("raw_tracepoint/block_bio_complete")
int obi_stats_raw_tp_block_bio_complete(struct bpf_raw_tracepoint_args *ctx) {
    struct bio *bio = (struct bio *)ctx->args[1];
    const u64 bio_key = (u64)(uintptr_t)bio;
    const disk_rq_start_t *start = bpf_map_lookup_elem(&disk_bio_start, &bio_key);
    if (!start) {
        return 0;
    }
    const u64 latency_ns = bpf_ktime_get_ns() - start->issued_ns;
    const u32 bytes = start->bytes;
    struct cgroup *cgrp = bio_cgroup(bio);
    const disk_io_key_t key = {
        .cgroup_id = cgroup_id_of(cgrp),
        .major = start->major,
        .minor = start->minor,
        .op = start->op,
        .status = BPF_CORE_READ(bio, bi_status),
    };
    bpf_map_delete_elem(&disk_bio_start, &bio_key);

    disk_io_accum_t *accum = lookup_or_init_accum(&disk_bio_accum, &key);
    if (!accum) {
        return 0;
    }
    if (cgrp) {
        record_cgroup_name(key.cgroup_id, cgrp);
    }
    if (key.status == 0) {
        __sync_fetch_and_add(&accum->bytes, bytes);
    }
    const u32 bucket =
        disk_latency_bucket(disk_latency_bounds_ns, disk_latency_bounds_len, latency_ns);
    if (bucket < k_disk_latency_max_buckets) {
        __sync_fetch_and_add(&accum->latency_count[bucket], 1);
        __sync_fetch_and_add(&accum->latency_sum_ns[bucket], latency_ns);
    }
    return 0;
}
