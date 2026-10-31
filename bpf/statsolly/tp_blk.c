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

// Set by userspace when block_rq_complete reports a blk_status_t instead of an errno
volatile const bool disk_status_is_blk_status;

// Set by userspace when the cgroups that the I/O is charged to are reported: otherwise the verifier
// leaves their reads out
volatile const bool disk_read_cgroup;

// The RQF_IO_STAT and RQF_FLUSH_SEQ request flags, which userspace finds in the kernel BTF: some
// kernels number them in an anonymous enum, and those that number them with macros get 0
volatile const u32 disk_rqf_io_stat;
volatile const u32 disk_rqf_flush_seq;

// REQ_OP_ZONE_APPEND, which userspace finds in the kernel BTF: its value depends on the kernel
// version
volatile const u32 disk_req_op_zone_append;

// Force structs into the ELF for automatic creation of Golang struct
const disk_io_key_t *unused_disk_io_key __attribute__((unused));
const disk_io_accum_t *unused_disk_io_accum __attribute__((unused));
const disk_cgroup_name_t *unused_disk_cgroup_name __attribute__((unused));

SCRATCH_MEM_TYPED(disk_io_accum_init, disk_io_accum_t)

// The operation of a block request is in the bits of its flags below the first request flag
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

// request_cgroup is the cgroup that a request is charged to: the io controller cgroup of its first
// bio, which the kernel charges in io.stat and io.max too. The requests that the block layer makes
// itself, like the flushes of a flush sequence, have none.
static __always_inline struct cgroup *request_cgroup(struct request *rq) {
    return bio_cgroup(BPF_CORE_READ(rq, bio));
}

// request_start is the start of a request at started_ns: its whole disk, its operation and its size
static __always_inline disk_rq_start_t request_start(struct request *rq,
                                                     const enum disk_op op,
                                                     const u64 started_ns) {
    struct gendisk *disk = request_disk(rq);
    const disk_rq_start_t start = {
        .issued_ns = started_ns,
        .bytes = BPF_CORE_READ(rq, __data_len),
        .major = BPF_CORE_READ(disk, major),
        .minor = BPF_CORE_READ(disk, first_minor),
        .op = op,
    };
    return start;
}

// record_issue records the issue of a request to the device, on OBI's clock. A request issued again
// after a requeue keeps its last issue.
static __always_inline void record_issue(struct request *rq) {
    const enum disk_op op = request_op(rq);
    if (op == disk_op_unknown) {
        return;
    }
    const disk_rq_start_t start = request_start(rq, op, bpf_ktime_get_ns());
    const u64 key = (u64)(uintptr_t)rq;
    bpf_map_update_elem(&disk_rq_start, &key, &start, BPF_ANY);
}

// Linux 5.11 (and 5.10.137 and RHEL 8.6) changed block_rq_issue from (q, rq) to (rq). Userspace
// loads the program that matches the prototype in the kernel BTF.
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

// never_issued tells whether a request completes without having been issued to the device: the
// empty flush write of a file sync, which the flush that it waited for completes, or a request that
// the driver fails before its issue, as the SCSI layer fails those of an offline device
static __always_inline bool never_issued(struct request *rq) {
    return BPF_CORE_READ(rq, state) == bpf_core_enum_value(enum mq_rq_state, MQ_RQ_IDLE);
}

// take_issue moves the issue record of a request into start. A request has none when it was issued
// before the probes were attached, when its record was evicted, or when the kernel skipped the issue
// program because it was already running on the CPU (counted in the program's recursion_misses).
static __always_inline bool take_issue(struct request *rq, disk_rq_start_t *start) {
    const u64 key = (u64)(uintptr_t)rq;
    const disk_rq_start_t *recorded = bpf_map_lookup_elem(&disk_rq_start, &key);
    if (!recorded) {
        return false;
    }
    *start = *recorded;
    // only the completion that deletes the record counts the request
    if (bpf_map_delete_elem(&disk_rq_start, &key) != 0) {
        return false;
    }
    // a record older than the start of the request belongs to an earlier use of its address, whose
    // completion was missed
    return start->issued_ns >= BPF_CORE_READ(rq, start_time_ns);
}

// take_start moves into start the issue record of a request, or, for a request that was never
// issued, the kernel's start of the request, as /proc/diskstats times it, which doesn't count it
// without one
static __always_inline bool
take_start(struct request *rq, const enum disk_op op, disk_rq_start_t *start) {
    if (!never_issued(rq)) {
        return take_issue(rq, start);
    }
    const u64 started_ns = disk_accounted_start_ns(BPF_CORE_READ(rq, start_time_ns),
                                                   BPF_CORE_READ(rq, rq_flags),
                                                   disk_rqf_io_stat,
                                                   disk_rqf_flush_seq);
    if (started_ns == 0) {
        return false;
    }
    *start = request_start(rq, op, started_ns);
    return true;
}

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

// A request is counted once, at its final completion, if that completion takes its issue record or
// the request was never issued: a write that the kernel completes again at the end of its flush
// sequence was issued, and has no record left.
SEC("raw_tracepoint/block_rq_complete")
int obi_stats_raw_tp_block_rq_complete(struct bpf_raw_tracepoint_args *ctx) {
    struct request *rq = (struct request *)ctx->args[0];
    const u32 nr_bytes = (u32)ctx->args[2];

    if (!disk_rq_final_completion(nr_bytes, BPF_CORE_READ(rq, __data_len))) {
        return 0;
    }
    // the operations that are not measured, like discards, have no issue record
    const enum disk_op op = request_op(rq);
    if (op == disk_op_unknown) {
        return 0;
    }
    disk_rq_start_t start;
    if (!take_start(rq, op, &start)) {
        return 0;
    }

    const u64 now_ns = bpf_ktime_get_ns();
    const u64 latency_ns = now_ns > start.issued_ns ? now_ns - start.issued_ns : 0;
    struct cgroup *cgrp = disk_read_cgroup ? request_cgroup(rq) : 0;
    const disk_io_key_t key = {
        .cgroup_id = cgroup_id_of(cgrp),
        .major = start.major,
        .minor = start.minor,
        .op = start.op,
        .status = disk_status_code(ctx->args[1], disk_status_is_blk_status),
    };
    disk_io_accum_t *accum = lookup_or_init_accum(&key);
    if (!accum) {
        return 0;
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
    return 0;
}
