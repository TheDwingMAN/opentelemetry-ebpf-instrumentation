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
#include <statsolly/maps/blk_bio_devs.h>
#include <statsolly/maps/blk_bio_inflight.h>

// Block I/O of bio-based stacked volumes (storage_block_volumes): an LVM
// logical volume, an md array, a dm-crypt device. Such a device has no
// request queue of its own: its driver clones every bio onto the devices
// below, so the request tracepoints (blk_io.c) only ever see the physical
// disks. These programs measure the volume itself, from block_bio_queue,
// when a bio is submitted to it, to block_bio_complete, when the last of
// what the driver made of it is done: the end-to-end time of the bio as its
// submitter sees it. They count in the maps of the request programs, under
// the volume's own device.
//
// The kernel traces both events once per bio (S0-b on dm-linear, dm-thin, md
// raid0 and raid1): a bio the driver splits is queued once and completes
// once, when its last fragment does. So the counts are bios as submitted to
// the volume, while /proc/diskstats of dm and md devices counts the
// fragments.
//
// block_bio_queue fires for every bio submitted on the node, whatever its
// device, so the path of a bio that is not tracked is kept short: three
// loads to the major of its gendisk and a comparison.

// The majors the set of tracked volumes has devices of, kept by userspace
// (blk_vol_major_match). A mutable global: the set changes while the programs
// run, when the first device-mapper volume appears on a node that had only md
// arrays, say.
u32 blk_vol_major[k_blk_vol_majors];

// REQ_PREFLUSH as a mask, or 0 on a kernel whose BTF does not name the bit.
// Its position has changed between kernels (18 on RHEL 9).
static __always_inline u32 blk_req_preflush_mask(void) {
    if (bpf_core_enum_value_exists(enum req_flag_bits, __REQ_PREFLUSH)) {
        return 1U << bpf_core_enum_value(enum req_flag_bits, __REQ_PREFLUSH);
    }
    return 0;
}

// blk_bio_tracked_dev returns the dev_t of the whole disk of a bio's gendisk
// when it is a tracked volume, else 0.
static __always_inline u32 blk_bio_tracked_dev(const u32 major, const u32 first_minor) {
    const u32 dev = blk_disk_devt((int)major, (int)first_minor);
    return bpf_map_lookup_elem(&blk_bio_devs, &dev) ? dev : 0;
}

static __always_inline enum blk_req_kind blk_bio_kind(const u32 opf, const u32 size) {
    return blk_kind_from_bio(opf, size, blk_req_op_zone_append(), blk_req_preflush_mask());
}

// Whether the queueing of a bio of kind reads the cgroup it is charged to:
// only the pod counters use it, and they count reads and writes only.
static __always_inline bool blk_bio_want_cgid(const enum blk_req_kind kind) {
    return blk_want_cgroup && blk_kind_is_read_write(kind);
}

// blk_bio_queued records a bio of kind queued on the tracked volume dev. Its
// bytes are taken now: the driver consumes bi_iter as it clones the bio, and
// by the completion bi_size is rarely what was submitted (S0-b: 10 of 2144
// reads on a thin volume kept it). pdev is the dev_t of the bio's
// block_device, which names the partition when the bio was submitted to one;
// cgid the cgroup it is charged to, read at queueing as for a request at its
// issue (S0-d: the same ids on the dm leaf as on the disk below).
static __always_inline void blk_bio_queued(const u64 bio,
                                           const u32 dev,
                                           const u32 pdev,
                                           const enum blk_req_kind kind,
                                           const u32 size,
                                           const u64 cgid) {
    struct blk_rq_inflight queued = {};
    queued.issue_ns = bpf_ktime_get_ns();
    queued.bytes_done = size;
    queued.cgid = cgid;
    queued.dev = dev;
    queued.part_dev = blk_part_dev(pdev, dev);
    queued.kind = kind;

    blk_inflight_begin(&blk_bio_inflight, &bio, &queued, true, k_stats_drop_blk_bio_inflight);
}

// blk_bio_completed counts the completed bio in done. There is no queue wait
// to count: a bio is timed from its submission, and what it waits for below
// the volume is part of its duration.
static __always_inline void blk_bio_completed(const struct blk_done *const done, const u8 status) {
    const int error = blk_status_to_errno(status);
    if (blk_emit_mode == k_blk_emit_agg) {
        const struct blk_agg_key key = blk_agg_key_of(&done->op, error);
        blk_agg_service(&key, done->bytes, done->svc_ns);
        return;
    }
    blk_emit_event(done, error);
}

// The completion of a bio that has no entry is not an error and has no
// effect: every bio-based device traces its completions, tracked or not, and
// a driver that splits a bio (md raid0 at a chunk boundary, raid1 around a
// bad block) completes each fragment under a pointer of its own, which was
// never queued (S0-b: 528 such completions for 32 writes of 1 MiB on a raid0
// with 64 KiB chunks). The device is not read back from the bio either: the
// entry has it, from the queueing.
static __always_inline bool blk_bio_end(const u64 bio, struct blk_done *const done) {
    return blk_inflight_end(&blk_bio_inflight, &bio, 0, true, done);
}

// The bio tracepoints are attached as tp_btf, reading the bio with direct
// loads, or as raw_tp, reading it through bpf_probe_read_kernel, as the
// request tracepoints are (blk_io.c). There is no classic-tracepoint
// variant: those do not carry the bio. Kernels before 5.11 pass the request
// queue before the bio to block_bio_queue; the _legacy programs take that
// shape, and the loader picks the variant the tracepoint's BTF prototype has.
//
// The device is the bio's gendisk, bio->bi_bdev->bd_disk. bi_bdev exists
// since Linux 5.12; on older kernels the loader does not load these programs.

static __always_inline void blk_tp_btf_bio_queue(const struct bio *const bio) {
    const struct block_device *const bdev = bio->bi_bdev;
    if (!bdev) {
        return;
    }
    const struct gendisk *const disk = bdev->bd_disk;
    if (!disk) {
        return;
    }
    const u32 major = (u32)disk->major;
    if (!blk_vol_major_match(blk_vol_major, major)) {
        return;
    }
    const u32 dev = blk_bio_tracked_dev(major, (u32)disk->first_minor);
    if (!dev) {
        return;
    }
    const u32 size = bio->bi_iter.bi_size;
    const enum blk_req_kind kind = blk_bio_kind(bio->bi_opf, size);
    if (kind == blk_req_ignore) {
        return;
    }
    blk_bio_queued((u64)bio,
                   dev,
                   blk_want_part ? bdev->bd_dev : dev,
                   kind,
                   size,
                   blk_bio_want_cgid(kind) ? blk_bio_cgid_btf(bio) : 0);
}

SEC("tp_btf/block_bio_queue")
int BPF_PROG(obi_stats_tp_btf_block_bio_queue, struct bio *bio) {
    blk_tp_btf_bio_queue(bio);
    return 0;
}

SEC("tp_btf/block_bio_queue")
int BPF_PROG(obi_stats_tp_btf_block_bio_queue_legacy, struct request_queue *q, struct bio *bio) {
    blk_tp_btf_bio_queue(bio);
    return 0;
}

SEC("tp_btf/block_bio_complete")
int BPF_PROG(obi_stats_tp_btf_block_bio_complete, struct request_queue *q, struct bio *bio) {
    struct blk_done done;
    if (blk_bio_end((u64)bio, &done)) {
        blk_bio_completed(&done, bio->bi_status);
    }
    return 0;
}

// raw_tp programs: the same tracepoints, the bio read through BPF_CORE_READ.

static __always_inline void blk_raw_tp_bio_queue(const struct bio *const bio) {
    const struct block_device *const bdev = BPF_CORE_READ(bio, bi_bdev);
    if (!bdev) {
        return;
    }
    const struct gendisk *const disk = BPF_CORE_READ(bdev, bd_disk);
    if (!disk) {
        return;
    }
    const u32 major = (u32)BPF_CORE_READ(disk, major);
    if (!blk_vol_major_match(blk_vol_major, major)) {
        return;
    }
    const u32 dev = blk_bio_tracked_dev(major, (u32)BPF_CORE_READ(disk, first_minor));
    if (!dev) {
        return;
    }
    const u32 size = BPF_CORE_READ(bio, bi_iter.bi_size);
    const enum blk_req_kind kind = blk_bio_kind(BPF_CORE_READ(bio, bi_opf), size);
    if (kind == blk_req_ignore) {
        return;
    }
    blk_bio_queued((u64)bio,
                   dev,
                   blk_want_part ? BPF_CORE_READ(bdev, bd_dev) : dev,
                   kind,
                   size,
                   blk_bio_want_cgid(kind) ? blk_bio_cgid(bio) : 0);
}

SEC("raw_tp/block_bio_queue")
int obi_stats_raw_tp_block_bio_queue(struct bpf_raw_tracepoint_args *ctx) {
    blk_raw_tp_bio_queue((const struct bio *)ctx->args[0]);
    return 0;
}

SEC("raw_tp/block_bio_queue")
int obi_stats_raw_tp_block_bio_queue_legacy(struct bpf_raw_tracepoint_args *ctx) {
    blk_raw_tp_bio_queue((const struct bio *)ctx->args[1]);
    return 0;
}

SEC("raw_tp/block_bio_complete")
int obi_stats_raw_tp_block_bio_complete(struct bpf_raw_tracepoint_args *ctx) {
    const struct bio *const bio = (const struct bio *)ctx->args[1];
    struct blk_done done;
    if (blk_bio_end((u64)bio, &done)) {
        blk_bio_completed(&done, BPF_CORE_READ(bio, bi_status));
    }
    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
