// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_core_read.h>

#include <statsolly/disk_accum.h>
#include <statsolly/disk_io.h>
#include <statsolly/types.h>
#include <statsolly/maps/disk_io_accum.h>
#include <statsolly/maps/disk_rq_start.h>

// The RQF_FLUSH_SEQ flag of struct request, which userspace finds in the kernel BTF: its bit
// depends on the kernel version, and some kernels number it in an anonymous enum.
volatile const u32 disk_rqf_flush_seq;
// The RQF_IO_STAT flag of struct request, which userspace finds in the kernel BTF: 0 where the
// kernel numbers its request flags with macros.
volatile const u32 disk_rqf_io_stat;

// Force structs into the ELF for automatic creation of Golang struct
const disk_io_key_t *unused_disk_io_key __attribute__((unused));
const disk_io_accum_t *unused_disk_io_accum __attribute__((unused));

static __always_inline enum disk_op request_op(struct request *rq) {
    return disk_op_from_req_op(BPF_CORE_READ(rq, cmd_flags) & k_op_mask, disk_req_op_zone_append);
}

static __always_inline struct gendisk *request_disk(struct request *rq) {
    // rq->rq_disk was removed in Linux 5.17 in favor of rq->q->disk, which older kernels
    // (including RHEL 8) don't have.
    if (bpf_core_field_exists(rq->rq_disk)) {
        return BPF_CORE_READ(rq, rq_disk);
    }
    return BPF_CORE_READ(rq, q, disk);
}

// request_start_ns is when the kernel started timing a request, or 0 if it didn't. rq_flags is only
// read on the kernels that need it.
static __always_inline u64 request_start_ns(struct request *rq) {
    const u64 start_ns = BPF_CORE_READ(rq, start_time_ns);
    if (disk_rqf_io_stat == 0) {
        return start_ns;
    }
    return disk_accounted_start_ns(start_ns, BPF_CORE_READ(rq, rq_flags), disk_rqf_io_stat);
}

// in_flush_sequence tells whether a request is a step of a flush sequence: the flush that the
// sequence issues, or a write with a cache flush before or after it, which the kernel completes
// once for its data and again at the end of the sequence
static __always_inline bool in_flush_sequence(struct request *rq) {
    return (BPF_CORE_READ(rq, rq_flags) & disk_rqf_flush_seq) != 0;
}

// never_issued tells whether a request completes without having been issued to the device, as
// the empty flush of an fsync does when the flush machinery completes it after the flush it
// waited for
static __always_inline bool never_issued(struct request *rq) {
    if (!bpf_core_field_exists(rq->state)) {
        return false;
    }
    return BPF_CORE_READ(rq, state) == bpf_core_enum_value(enum mq_rq_state, MQ_RQ_IDLE);
}

// record_issue records when a request is issued to the device, on OBI's clock. A request issued
// again after a requeue keeps its last issue. The kernel's own timestamps are only a fallback (see
// kernel_issue_start): from Linux 6.9 (and RHEL 9.6), they read the clock cached by the
// submitter's block plug, which can be hundreds of milliseconds old for writeback.
static __always_inline void record_issue(struct request *rq) {
    const enum disk_op op = request_op(rq);
    if (op == disk_op_unknown) {
        return;
    }
    const u64 issued_ns = bpf_ktime_get_ns();
    struct gendisk *disk = request_disk(rq);
    const u64 key = (u64)(uintptr_t)rq;
    const disk_rq_start_t start = {
        .issued_ns = issued_ns,
        .major = BPF_CORE_READ(disk, major),
        .minor = BPF_CORE_READ(disk, first_minor),
        .op = op,
    };
    bpf_map_update_elem(&disk_rq_start, &key, &start, BPF_ANY);
}

// Block layer tracepoint arguments changed in Linux 5.11 (also backported to 5.10.137+ and
// RHEL 8.6+): block_rq_issue went from (q, rq) to (rq). Userspace loads one of the two
// programs below after checking the tracepoint prototype in the kernel BTF.
SEC("raw_tracepoint/block_rq_issue")
int obi_stats_raw_tp_block_rq_issue(struct bpf_raw_tracepoint_args *ctx) {
    record_issue((struct request *)ctx->args[0]);
    return 0;
}

SEC("raw_tracepoint/block_rq_issue")
int obi_stats_raw_tp_block_rq_issue_legacy(struct bpf_raw_tracepoint_args *ctx) {
    record_issue((struct request *)ctx->args[1]);
    return 0;
}

// recorded_start moves what record_issue recorded of a request into start. A request is not
// recorded when it was issued before the probes were attached, or when the kernel skipped
// record_issue because another BPF program was running on the CPU (recursion_misses).
static __always_inline bool recorded_start(struct request *rq, disk_rq_start_t *start) {
    const u64 rq_key = (u64)(uintptr_t)rq;
    const disk_rq_start_t *recorded = bpf_map_lookup_elem(&disk_rq_start, &rq_key);
    if (!recorded) {
        return false;
    }
    // what was recorded before the request started belongs to an earlier use of the same address,
    // whose completion was missed. A start left by an earlier use (see disk_accounted_start_ns) is
    // older than this use, so it can only miss such a record.
    const u64 started_ns = BPF_CORE_READ(rq, start_time_ns);
    if (recorded->issued_ns < started_ns) {
        bpf_map_delete_elem(&disk_rq_start, &rq_key);
        return false;
    }
    *start = *recorded;
    bpf_map_delete_elem(&disk_rq_start, &rq_key);
    return true;
}

// kernel_issue_start fills start for an issued request that record_issue didn't record, from the
// issue time that the kernel recorded, if it times the requests of the queue (QUEUE_FLAG_STATS), or
// else from its start, so that the request is still counted.
static __always_inline bool kernel_issue_start(struct request *rq, disk_rq_start_t *start) {
    u64 started_ns = 0;
    if (bpf_core_field_exists(rq->io_start_time_ns)) {
        started_ns = BPF_CORE_READ(rq, io_start_time_ns);
    }
    if (started_ns == 0) {
        started_ns = request_start_ns(rq);
    }
    if (started_ns == 0) {
        return false;
    }
    struct gendisk *disk = request_disk(rq);
    start->issued_ns = started_ns;
    start->major = BPF_CORE_READ(disk, major);
    start->minor = BPF_CORE_READ(disk, first_minor);
    start->op = request_op(rq);
    return true;
}

// never_issued_start fills start for a request that was never issued, which OBI has no issue time
// for: from when the kernel started timing it, as it also does in /proc/diskstats. The kernel
// doesn't count requests that it doesn't time.
static __always_inline bool never_issued_start(struct request *rq, disk_rq_start_t *start) {
    const u64 started_ns = request_start_ns(rq);
    if (started_ns == 0) {
        return false;
    }
    struct gendisk *disk = request_disk(rq);
    start->issued_ns = started_ns;
    start->major = BPF_CORE_READ(disk, major);
    start->minor = BPF_CORE_READ(disk, first_minor);
    start->op = request_op(rq);
    return true;
}

SEC("raw_tracepoint/block_rq_complete")
int obi_stats_raw_tp_block_rq_complete(struct bpf_raw_tracepoint_args *ctx) {
    struct request *rq = (struct request *)ctx->args[0];
    const u8 status = disk_status_code(ctx->args[1], disk_status_is_blk_status);
    const u32 nr_bytes = (u32)ctx->args[2];

    if (!disk_rq_final_completion(nr_bytes, BPF_CORE_READ(rq, __data_len))) {
        return 0;
    }

    // the operations that OBI doesn't measure (flush, discard, passthrough, zone management) must
    // not reach the maps: from Linux 6.8 the kernel doesn't time passthrough commands, and their
    // completion would stop the timing of the queue
    const enum disk_op op = request_op(rq);
    if (op == disk_op_unknown) {
        return 0;
    }

    // the kernel completes a write with a cache flush before or after it again at the end of its
    // flush sequence, and only counts it then
    if (in_flush_sequence(rq)) {
        return 0;
    }

    // it was counted when its bytes completed
    if (disk_rq_completed_before(
            nr_bytes, BPF_CORE_READ(rq, bio) != 0, BPF_CORE_READ(rq, biotail) != 0)) {
        return 0;
    }

    disk_rq_start_t start = {};
    if (never_issued(rq)) {
        if (!never_issued_start(rq, &start)) {
            return 0;
        }
    } else if (!recorded_start(rq, &start) && !kernel_issue_start(rq, &start)) {
        return 0;
    }
    const u64 now_ns = bpf_ktime_get_ns();
    const u64 latency_ns = now_ns > start.issued_ns ? now_ns - start.issued_ns : 0;
    const disk_io_key_t key = {
        .major = start.major,
        .minor = start.minor,
        .op = start.op,
        .status = status,
    };

    disk_io_accum_t *accum = lookup_or_init_accum(&disk_io_accum, &key);
    if (!accum) {
        return 0;
    }
    const u32 bucket = disk_latency_bucket(disk_latency_bounds_ns, latency_ns);
    if (bucket < k_disk_latency_buckets) {
        __sync_fetch_and_add(&accum->latency_count[bucket], 1);
        __sync_fetch_and_add(&accum->latency_sum_ns, latency_ns);
    }
    return 0;
}
