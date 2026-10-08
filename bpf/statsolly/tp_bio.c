// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_core_read.h>

#include <statsolly/cgroup_names.h>
#include <statsolly/disk_attrs.h>
#include <statsolly/disk_accum.h>
#include <statsolly/disk_io.h>
#include <statsolly/types.h>
#include <statsolly/maps/disk_bio_accum.h>
#include <statsolly/maps/disk_bio_devices.h>
#include <statsolly/maps/disk_bio_start.h>

// Bio-based devices, such as device mapper (LVM, dm-crypt) and md RAID volumes, the heads of NVMe
// native multipath and the disks of drivers that handle bios themselves (PowerFlex SDC, DRBD,
// zram), never issue requests of their own. Their I/O is measured from the bio that is submitted
// to them until its completion.

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
    return disk_bio_op(BPF_CORE_READ(bio, bi_opf),
                       k_op_mask,
                       preflush_flag,
                       disk_req_op_zone_append,
                       BPF_CORE_READ(bio, bi_iter.bi_size));
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

// complete_bio counts the completion of a bio that record_bio_queue recorded, with its
// blk_status_t, and forgets the bio: a bio that is not recorded, or already counted, is skipped
static __always_inline void complete_bio(struct bio *bio, const u8 status) {
    const u64 bio_key = (u64)(uintptr_t)bio;
    const disk_rq_start_t *start = bpf_map_lookup_elem(&disk_bio_start, &bio_key);
    if (!start) {
        return;
    }
    const u64 latency_ns = bpf_ktime_get_ns() - start->issued_ns;
    const u32 bytes = start->bytes;
    struct cgroup *cgrp = disk_read_cgroup ? bio_cgroup(bio) : 0;
    const disk_io_key_t key = {
        .cgroup_id = cgroup_id_of(cgrp),
        .major = start->major,
        .minor = start->minor,
        .op = start->op,
        .status = status,
    };
    bpf_map_delete_elem(&disk_bio_start, &bio_key);

    disk_io_accum_t *accum = lookup_or_init_accum(&disk_bio_accum, &key);
    if (!accum) {
        return;
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
}

// block_bio_complete is (q, bio) on every supported kernel
SEC("raw_tracepoint/block_bio_complete")
int obi_stats_raw_tp_block_bio_complete(struct bpf_raw_tracepoint_args *ctx) {
    struct bio *bio = (struct bio *)ctx->args[1];
    complete_bio(bio, BPF_CORE_READ(bio, bi_status));
    return 0;
}

// The head device of NVMe native multipath hands its bios on to its paths as they are, and a path
// can merge them with other bios into a request. The kernel traces the completion of the request
// instead of the completion of its bios, and the NVMe driver traces the completion of the first bio
// of each request on the head (nvme_trace_bio_complete), but not of the bios merged after it, nor
// of the empty flush of a file sync, which the path completes without the driver. Those bios are
// completed here, from the completion of their request.

// The most bios that a completion of a request completes here: the NVMe PCIe driver gives a
// request 128 segments at most (NVME_MAX_SEGS), and a bio with data has one at least. The bios
// after them, which only discards of up to 256 ranges and the paths of NVMe over fabrics with
// larger requests can have, stay in disk_bio_start uncounted until newer bios evict them.
enum { k_disk_rq_max_bios = 128 };

// carries_mpath_bios tells whether a request may carry the bios of an NVMe native multipath head:
// the head marks the bios that it hands on with REQ_NVME_MPATH, which is REQ_DRV, and a request
// has the flags of its first bio. Without __REQ_DRV in the kernel BTF, no request is walked.
static __always_inline bool carries_mpath_bios(struct request *rq) {
    if (!bpf_core_enum_value_exists(enum req_flag_bits, __REQ_DRV)) {
        return false;
    }
    const u32 drv_flag = 1U << bpf_core_enum_value(enum req_flag_bits, __REQ_DRV);
    return (BPF_CORE_READ(rq, cmd_flags) & drv_flag) != 0;
}

// complete_request_bio completes a bio of a request. It is a global function, which the verifier
// checks once, on its own: inlined, complete_bio would be checked again for each bio of the walk,
// with a cost that grows faster than the bound. Its arguments are scalars, as global functions
// require.
__noinline int complete_request_bio(const u64 bio, const u8 status) {
    complete_bio((struct bio *)bio, status);
    return 0;
}

// block_rq_complete is (rq, error, nr_bytes) on every supported kernel. It fires before the kernel
// advances the bios of the request, which are completed as the kernel completes them. Completing a
// bio twice is harmless, as complete_bio forgets it: nvme_trace_bio_complete fires before this
// completion, and a request in a flush sequence is completed again at its end.
SEC("raw_tracepoint/block_rq_complete")
int obi_stats_raw_tp_block_rq_complete_bios(struct bpf_raw_tracepoint_args *ctx) {
    struct request *rq = (struct request *)ctx->args[0];
    if (!carries_mpath_bios(rq)) {
        return 0;
    }
    const u8 status = disk_bio_status(ctx->args[1], disk_status_is_blk_status);
    u32 bytes_left = (u32)ctx->args[2];
    struct bio *bio = BPF_CORE_READ(rq, bio);
    for (u32 i = 0; i < k_disk_rq_max_bios && bio; i++) {
        const u32 bio_bytes = BPF_CORE_READ(bio, bi_iter.bi_size);
        if (!disk_rq_completes_bio(bio_bytes, bytes_left)) {
            break;
        }
        complete_request_bio((u64)(uintptr_t)bio, status);
        // the kernel stops once the bytes of the completion are used up
        bytes_left -= bio_bytes;
        if (bytes_left == 0) {
            break;
        }
        bio = BPF_CORE_READ(bio, bi_next);
    }
    return 0;
}
