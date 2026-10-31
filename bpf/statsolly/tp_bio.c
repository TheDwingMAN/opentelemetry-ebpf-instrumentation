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
#include <statsolly/maps/disk_bio_start.h>
#include <statsolly/maps/disk_io_accum.h>

// The bio-based block devices, like the device mapper and md RAID volumes, the heads of NVMe native
// multipath and the disks of the drivers that handle bios themselves (zram, pmem, brd), issue no
// requests of their own: their I/O is measured from each bio submitted to them until its completion.
// The kernel traces the submission of a bio once, on the device that it is submitted to, and its
// completion while that trace flag is set: a bio that becomes part of a request loses the flag, as
// the completion of the request is traced instead.

// bio fields of the kernels before Linux 5.12 (and RHEL 8), which had no bi_bdev
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

// disk_issues_requests tells whether a disk issues requests: its queue has blk-mq operations
// (queue_is_mq). A bio-based disk has none, and on every supported kernel the other disks have them:
// Linux 5.0 removed the legacy single-queue path, and so did the RHEL 8 kernel, whose request_queue
// has no request_fn.
static __always_inline bool disk_issues_requests(struct gendisk *disk) {
    return BPF_CORE_READ(disk, queue, mq_ops) != 0;
}

// bio_op is the operation of a bio of size bytes: the completion classifies with the recorded size,
// as bi_size is 0 at the completion of the bios that went through a request
static __always_inline enum disk_op bio_op(struct bio *bio, const u32 size) {
    const u32 preflush_flag = 1U << bpf_core_enum_value(enum req_flag_bits, __REQ_PREFLUSH);
    return disk_bio_op(
        BPF_CORE_READ(bio, bi_opf), k_op_mask, preflush_flag, disk_req_op_zone_append, size);
}

// record_bio_queue records the submission of a bio to a bio-based disk, on OBI's clock
static __always_inline void record_bio_queue(struct bio *bio) {
    struct gendisk *disk = bio_disk(bio);
    if (disk_issues_requests(disk)) {
        return;
    }
    const u32 size = BPF_CORE_READ(bio, bi_iter.bi_size);
    const enum disk_op op = bio_op(bio, size);
    if (op == disk_op_unknown) {
        return;
    }
    const disk_rq_start_t start = {
        .issued_ns = bpf_ktime_get_ns(),
        .bytes = size,
        .major = BPF_CORE_READ(disk, major),
        .minor = BPF_CORE_READ(disk, first_minor),
        .op = op,
    };
    const u64 key = (u64)(uintptr_t)bio;
    bpf_map_update_elem(&disk_bio_start, &key, &start, BPF_ANY);
}

// Linux 5.11 changed block_bio_queue from (q, bio) to (bio), apart from block_rq_issue (5.10.137 and
// RHEL 8.6 backported only the latter). Userspace loads the program that matches the prototype in
// the kernel BTF.
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

// take_bio_start moves the record of a bio into start. A bio has none when it was submitted before
// the probes were attached, or to a disk that issues requests, when its record was evicted, or when
// the kernel skipped the queue program (counted in its recursion_misses). Bios come from a slab: a
// record whose completion was missed belongs to an earlier bio at the same address, and is dropped
// when the completing bio's operation isn't the recorded one.
static __always_inline bool take_bio_start(struct bio *bio, disk_rq_start_t *start) {
    const u64 key = (u64)(uintptr_t)bio;
    const disk_rq_start_t *recorded = bpf_map_lookup_elem(&disk_bio_start, &key);
    if (!recorded) {
        return false;
    }
    *start = *recorded;
    // only the completion that deletes the record counts the bio
    if (bpf_map_delete_elem(&disk_bio_start, &key) != 0) {
        return false;
    }
    return bio_op(bio, start->bytes) == start->op;
}

// complete_bio counts the completion of a recorded bio at now_ns, with its status
static __always_inline void complete_bio(struct bio *bio, const u8 status, const u64 now_ns) {
    disk_rq_start_t start;
    if (!take_bio_start(bio, &start)) {
        return;
    }
    const u64 latency_ns = now_ns > start.issued_ns ? now_ns - start.issued_ns : 0;
    struct cgroup *cgrp = disk_read_cgroup ? bio_cgroup(bio) : 0;
    const disk_io_key_t key = {
        .cgroup_id = cgroup_id_of(cgrp),
        .major = start.major,
        .minor = start.minor,
        .op = start.op,
        .status = status,
        .bio = 1,
    };
    disk_io_accum_t *accum = lookup_or_init_accum(&key);
    if (!accum) {
        return;
    }
    if (cgrp) {
        record_cgroup_name(key.cgroup_id, cgrp);
    }
    const u32 bucket = disk_latency_bucket(disk_latency_bounds_ns, latency_ns);
    __sync_fetch_and_add(&accum->latency_count[bucket], 1);
    __sync_fetch_and_add(&accum->latency_sum_ns, latency_ns);
    if (key.status == 0) {
        __sync_fetch_and_add(&accum->bytes, start.bytes);
    }
}

// block_bio_complete is (q, bio) on every supported kernel, and was (q, bio, error) before Linux
// 5.8: the bio is args[1] under both. bi_status is a blk_status_t on every kernel. A bio that sits on
// a disk that issues requests is left to block_rq_complete_bios, which has the status of its request:
// the NVMe driver traces the first bio of each request of a multipath head before the kernel sets
// the bio's status. A bio that the path fails before it becomes a request leaves its record, like a
// skipped completion.
SEC("raw_tracepoint/block_bio_complete")
int obi_stats_raw_tp_block_bio_complete(struct bpf_raw_tracepoint_args *ctx) {
    struct bio *bio = (struct bio *)ctx->args[1];
    if (disk_issues_requests(bio_disk(bio))) {
        return 0;
    }
    complete_bio(bio, BPF_CORE_READ(bio, bi_status), bpf_ktime_get_ns());
    return 0;
}

// The head of NVMe native multipath hands its bios to a path as they are, and the path merges them
// into requests. The kernel then traces the completion of each request instead of that of its bios,
// and the NVMe driver traces the first bio of each request on the head, before the kernel sets its
// status: not the bios merged after it, nor the empty flush of a file sync, which the flush sequence
// completes without the driver. So the bios of those requests are completed here, from the
// completion of their request and with its status.

// The most bios that a completion of a request completes here: the NVMe PCIe driver gives a request
// 128 segments at most (NVME_MAX_SEGS), and a bio with data has one at least. The bios after them,
// which only the paths of NVMe over fabrics with larger requests can have, stay in disk_bio_start
// until newer bios evict them.
enum { k_disk_rq_max_bios = 128 };

// carries_mpath_bios tells whether a request may carry the bios of an NVMe native multipath head:
// the head marks the bios that it hands on with REQ_NVME_MPATH, which is REQ_DRV, and a request has
// the flags of its first bio. Without __REQ_DRV in the kernel BTF, no request is walked.
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
__noinline int complete_request_bio(const u64 bio, const u8 status, const u64 now_ns) {
    complete_bio((struct bio *)bio, status, now_ns);
    return 0;
}

// block_rq_complete is (rq, error, nr_bytes) on every supported kernel. It fires before the kernel
// advances the bios of the request, which are completed as the kernel completes them. A bio that the
// kernel completes again, as a request of a flush sequence at its end, has no record left.
SEC("raw_tracepoint/block_rq_complete")
int obi_stats_raw_tp_block_rq_complete_bios(struct bpf_raw_tracepoint_args *ctx) {
    struct request *rq = (struct request *)ctx->args[0];
    if (!carries_mpath_bios(rq)) {
        return 0;
    }
    const u8 status = disk_bio_status(ctx->args[1], disk_status_is_blk_status);
    const u64 now_ns = bpf_ktime_get_ns();
    u32 bytes_left = (u32)ctx->args[2];
    struct bio *bio = BPF_CORE_READ(rq, bio);
    for (u32 i = 0; i < k_disk_rq_max_bios && bio; i++) {
        const u32 bio_bytes = BPF_CORE_READ(bio, bi_iter.bi_size);
        if (!disk_rq_completes_bio(bio_bytes, bytes_left)) {
            break;
        }
        complete_request_bio((u64)(uintptr_t)bio, status, now_ns);
        // the kernel stops once the bytes of the completion are used up
        bytes_left -= bio_bytes;
        if (bytes_left == 0) {
            break;
        }
        bio = BPF_CORE_READ(bio, bi_next);
    }
    return 0;
}
