// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_builtins.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_core_read.h>

#include <common/scratch_mem.h>

#include <statsolly/cgroup_names.h>
#include <statsolly/disk_io.h>
#include <statsolly/types.h>
#include <statsolly/maps/disk_io_accum.h>
#include <statsolly/maps/disk_rq_start.h>

// The latency histogram boundaries of block requests. To be injected from userspace
// during eBPF program load & initialization.
volatile const u64 disk_latency_bounds_ns[k_disk_latency_bounds];

// REQ_OP_ZONE_APPEND, which userspace finds in the kernel BTF: its value depends on the kernel
// version. 0 when the kernel has none.
volatile const u32 disk_req_op_zone_append;

// Set when block_rq_complete reports a blk_status_t (Linux 5.16+) instead of a negative errno.
volatile const bool disk_status_is_blk_status;

// The RQF_FLUSH_SEQ flag of struct request, which userspace finds in the kernel BTF: its bit
// depends on the kernel version, and some kernels number it in an anonymous enum.
volatile const u32 disk_rqf_flush_seq;
// The RQF_IO_STAT flag of struct request, which userspace finds in the kernel BTF: 0 where the
// kernel numbers its request flags with macros.
volatile const u32 disk_rqf_io_stat;

// Set by userspace when an enabled block I/O metric reports, or a stats filter matches, an attribute
// of the workload that the I/O is charged to (container.id, the Kubernetes pod and workload, but not
// the cluster), which the probes find from its cgroup, or under dynamic application selection.
// Otherwise the probes don't read the cgroup.
volatile const bool disk_read_cgroup;

// Force structs into the ELF for automatic creation of Golang struct
const disk_io_key_t *unused_disk_io_key __attribute__((unused));
const disk_io_accum_t *unused_disk_io_accum __attribute__((unused));
const disk_cgroup_name_t *unused_disk_cgroup_name __attribute__((unused));

SCRATCH_MEM_TYPED(disk_io_accum_init, disk_io_accum_t)

// The operation of block request flags: the request flags start right after the
// REQ_OP_BITS-wide operation field.
enum { k_op_mask = (1U << __REQ_FAILFAST_DEV) - 1 };

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

// request_cgroup is the cgroup a request is charged to: the io controller cgroup of its first bio,
// which the kernel also charges in io.stat and io.max. Requests that the block layer makes itself,
// such as the flushes of a flush sequence, have no bio.
static __always_inline struct cgroup *request_cgroup(struct request *rq) {
    return bio_cgroup(BPF_CORE_READ(rq, bio));
}

// request_start_ns is when the kernel started timing a request, or 0 if it didn't. rq_flags is only
// read on the kernels that need it.
static __always_inline u64 request_start_ns(struct request *rq) {
    const u64 start_ns = BPF_CORE_READ(rq, start_time_ns);
    if (disk_rqf_io_stat == 0) {
        return start_ns;
    }
    return disk_accounted_start_ns(
        start_ns, BPF_CORE_READ(rq, rq_flags), disk_rqf_io_stat, disk_rqf_flush_seq);
}

// in_flush_sequence tells whether a request is a step of a flush sequence: the flush that the
// sequence issues, or a write with a cache flush before or after it, which the kernel completes
// once for its data and again at the end of the sequence
static __always_inline bool in_flush_sequence(struct request *rq) {
    return (BPF_CORE_READ(rq, rq_flags) & disk_rqf_flush_seq) != 0;
}

// never_issued tells whether a request completes without having been issued to the device, as
// the empty flush of an fsync does when the flush machinery completes it after the flush it
// waited for, and as a request that the driver fails before issuing it, like those of an offline
// SCSI device
static __always_inline bool never_issued(struct request *rq) {
    if (!bpf_core_field_exists(rq->state)) {
        return false;
    }
    return BPF_CORE_READ(rq, state) == bpf_core_enum_value(enum mq_rq_state, MQ_RQ_IDLE);
}

// fill_start fills start with the whole disk of a request, its operation, its size and when it
// started
static __always_inline void fill_start(struct request *rq,
                                       const enum disk_op op,
                                       const u32 bytes,
                                       const u64 started_ns,
                                       disk_rq_start_t *start) {
    struct gendisk *disk = request_disk(rq);
    start->issued_ns = started_ns;
    start->bytes = bytes;
    start->major = BPF_CORE_READ(disk, major);
    start->minor = BPF_CORE_READ(disk, first_minor);
    start->op = op;
}

// record_issue records when a request is issued to the device, on OBI's clock. A request issued
// again after a requeue keeps its last issue. The kernel's own timestamps are only a fallback (see
// kernel_start_ns): from Linux 6.9 (and RHEL 9.6), they read the clock cached by the
// submitter's block plug, which can be hundreds of milliseconds old for writeback.
static __always_inline void record_issue(struct request *rq) {
    const enum disk_op op = request_op(rq);
    if (op == disk_op_unknown) {
        return;
    }
    const u64 key = (u64)(uintptr_t)rq;
    disk_rq_start_t start = {};
    fill_start(rq, op, BPF_CORE_READ(rq, __data_len), bpf_ktime_get_ns(), &start);
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
// recorded when it was issued before the probes were attached, when its record was evicted from
// the LRU map, or when the kernel skipped record_issue because the same issue program was already
// running on the CPU, as when an interrupt issued a request during it: from Linux 6.2, raw
// tracepoint programs don't re-enter themselves on a CPU, and the kernel counts the runs it skips
// in the program's recursion_misses.
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

// kernel_start_ns is the kernel's own start of a request that record_issue didn't record, or 0 if
// the kernel didn't time it. An issued request starts at the issue time that the kernel recorded, if
// it times the requests of the queue (QUEUE_FLAG_STATS), or else at its start, so that the request
// is still counted. A request that was never issued has no issue time: it starts when the kernel
// started timing it, as in /proc/diskstats.
static __always_inline u64 kernel_start_ns(struct request *rq, const bool issued) {
    if (issued && bpf_core_field_exists(rq->io_start_time_ns)) {
        const u64 issued_ns = BPF_CORE_READ(rq, io_start_time_ns);
        if (issued_ns != 0) {
            return issued_ns;
        }
    }
    return request_start_ns(rq);
}

// lookup_or_init_accum returns the accumulation entry of a key, created zeroed if missing
static __always_inline disk_io_accum_t *lookup_or_init_accum(const disk_io_key_t *key) {
    disk_io_accum_t *accum = bpf_map_lookup_elem(&disk_io_accum, key);
    if (accum) {
        return accum;
    }
    disk_io_accum_t *init = disk_io_accum_init_mem();
    if (!init) {
        return 0;
    }
    bpf_memset(init, 0, sizeof(*init));
    // BPF_NOEXIST: another CPU may have created the entry since the lookup above
    bpf_map_update_elem(&disk_io_accum, key, init, BPF_NOEXIST);
    return bpf_map_lookup_elem(&disk_io_accum, key);
}

SEC("raw_tracepoint/block_rq_complete")
int obi_stats_raw_tp_block_rq_complete(struct bpf_raw_tracepoint_args *ctx) {
    struct request *rq = (struct request *)ctx->args[0];
    const u8 status = disk_status_code(ctx->args[1], disk_status_is_blk_status);
    const u32 nr_bytes = (u32)ctx->args[2];

    if (!disk_rq_final_completion(nr_bytes, BPF_CORE_READ(rq, __data_len))) {
        return 0;
    }

    // the operations that OBI doesn't measure (discard, passthrough, zone management) must not
    // reach the maps: from Linux 6.8 the kernel doesn't time passthrough commands, and their
    // completion would stop the timing of the queue
    const enum disk_op op = request_op(rq);
    if (op == disk_op_unknown) {
        return 0;
    }

    // the kernel completes a write with a cache flush before or after it again at the end of its
    // flush sequence, and only counts it then. The flush that the sequence issues to the device is
    // measured once, whatever the number of sequences it serves.
    if (in_flush_sequence(rq) && op != disk_op_flush) {
        return 0;
    }

    // it was counted when its bytes completed
    if (disk_rq_completed_before(
            nr_bytes, BPF_CORE_READ(rq, bio) != 0, BPF_CORE_READ(rq, biotail) != 0)) {
        return 0;
    }

    disk_rq_start_t start = {};
    const bool issued = !never_issued(rq);
    if (!issued || !recorded_start(rq, &start)) {
        const u64 started_ns = kernel_start_ns(rq, issued);
        // the kernel doesn't count the requests that it doesn't time
        if (started_ns == 0) {
            return 0;
        }
        // its size at issue is unknown: it is counted with the bytes of its final completion
        fill_start(rq, op, nr_bytes, started_ns, &start);
    }
    const u64 now_ns = bpf_ktime_get_ns();
    const u64 latency_ns = now_ns > start.issued_ns ? now_ns - start.issued_ns : 0;
    struct cgroup *cgrp = disk_read_cgroup ? request_cgroup(rq) : 0;
    const disk_io_key_t key = {
        .cgroup_id = cgroup_id_of(cgrp),
        .major = start.major,
        .minor = start.minor,
        .op = start.op,
        .status = status,
    };

    disk_io_accum_t *accum = lookup_or_init_accum(&key);
    if (!accum) {
        return 0;
    }
    if (cgrp) {
        record_cgroup_name(key.cgroup_id, cgrp);
    }
    const u32 bucket = disk_latency_bucket(disk_latency_bounds_ns, latency_ns);
    if (bucket >= k_disk_latency_buckets) {
        return 0;
    }
    // the request is counted last, so that a read of the entry that counts it also has its bytes
    // and its latency: userspace holds what a read finds added before the count until it is counted
    if (status == 0) {
        __sync_fetch_and_add(&accum->bytes, start.bytes);
    }
    __sync_fetch_and_add(&accum->latency_sum_ns, latency_ns);
    __sync_fetch_and_add(&accum->latency_count[bucket], 1);
    return 0;
}
