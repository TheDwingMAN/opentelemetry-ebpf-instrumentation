// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Run from repo root:
//   make -C bpf/tests test_blk_helpers && bpf/tests/test_blk_helpers
// Run from bpf/tests:
//   make test_blk_helpers && ./test_blk_helpers

#include <stdbool.h>
#include <stdio.h>

#include <statsolly/blk_helpers.h>

static unsigned int failed_assertions;

static void assert_true(bool condition, const char *message) {
    if (condition) {
        printf("PASS: %s\n", message);
        return;
    }

    failed_assertions++;
    printf("FAIL: %s\n", message);
}

static void test_status_to_errno(void) {
    assert_true(blk_status_to_errno(k_blk_sts_ok) == 0, "BLK_STS_OK is no error");
    assert_true(blk_status_to_errno(k_blk_sts_notsupp) == -95, "BLK_STS_NOTSUPP is EOPNOTSUPP");
    assert_true(blk_status_to_errno(k_blk_sts_timeout) == -110, "BLK_STS_TIMEOUT is ETIMEDOUT");
    assert_true(blk_status_to_errno(k_blk_sts_nospc) == -28, "BLK_STS_NOSPC is ENOSPC");
    assert_true(blk_status_to_errno(k_blk_sts_transport) == -67, "BLK_STS_TRANSPORT is ENOLINK");
    assert_true(blk_status_to_errno(k_blk_sts_target) == -121, "BLK_STS_TARGET is EREMOTEIO");
    assert_true(blk_status_to_errno(k_blk_sts_medium) == -61, "BLK_STS_MEDIUM is ENODATA");
    assert_true(blk_status_to_errno(k_blk_sts_resource) == -12, "BLK_STS_RESOURCE is ENOMEM");
    assert_true(blk_status_to_errno(k_blk_sts_ioerr) == -5, "BLK_STS_IOERR is EIO");
    assert_true(blk_status_to_errno(6) == -5, "an unmapped status (BLK_STS_NEXUS) is EIO");
    assert_true(blk_status_to_errno(255) == -5, "an unknown status is EIO");
}

static void test_final_chunk(void) {
    assert_true(blk_rq_final_chunk(4096, 4096, 0),
                "a completion covering the whole request ends it");
    assert_true(!blk_rq_final_chunk(1024, 4096, 0),
                "a partial completion (SCSI good_bytes) does not end the request");
    assert_true(blk_rq_final_chunk(3072, 3072, 0),
                "the chunk covering what is left ends the request");
    assert_true(blk_rq_final_chunk(0, 0, 0), "a flush, which carries no data, ends");
    assert_true(blk_rq_final_chunk(512, 4096, -61),
                "a failed chunk ends the request even when data is left");
    assert_true(blk_rq_final_chunk(8192, 4096, 0),
                "a completion larger than what is left ends the request");
}

// block_rq_complete's error argument, as __bpf_trace_block_rq_complete widens
// it into the program's u64 context: a blk_status_t byte zero-extended, an
// int errno sign-extended.
static void test_complete_error(void) {
    const u64 eopnotsupp_arg = (u64)(s64)-95;
    assert_true(blk_complete_error(eopnotsupp_arg, true) == -95,
                "an int errno kernel's -95 is EOPNOTSUPP");
    assert_true(blk_complete_error(eopnotsupp_arg, false) == -5,
                "the same argument read as blk_status_t (0xa1) is EIO: why the layout matters");
    assert_true(blk_complete_error((u64)(s64)-110, true) == -110, "an int errno ETIMEDOUT stays");
    assert_true(blk_complete_error(0, true) == 0, "errno 0 is no error");
    assert_true(blk_complete_error(k_blk_sts_notsupp, false) == -95,
                "BLK_STS_NOTSUPP on a blk_status_t kernel is EOPNOTSUPP");
    assert_true(blk_complete_error(k_blk_sts_ok, false) == 0, "BLK_STS_OK is no error");
    assert_true(blk_rq_final_chunk(512, 4096, blk_complete_error(eopnotsupp_arg, true)),
                "an int errno failure ends the request");
}

static struct blk_rq_inflight inflight(const u64 issue_ns,
                                       const u64 queue_ns,
                                       const u64 bytes_done,
                                       const u32 dev,
                                       const enum blk_req_kind kind) {
    struct blk_rq_inflight v = {};
    v.issue_ns = issue_ns;
    v.queue_ns = queue_ns;
    v.bytes_done = bytes_done;
    v.dev = dev;
    v.kind = kind;
    return v;
}

enum {
    k_dev_vda = (252 << 20) | 0,
    k_dev_vdb = (252 << 20) | 16,
};

static void test_requeue_overwrites_the_entry(void) {
    // A plain requeue (the driver was busy) of a request with no completion
    // yet: the new issue replaces the entry.
    struct blk_rq_inflight cur = inflight(100, 5, 0, k_dev_vda, blk_req_write);
    const struct blk_rq_inflight requeued = inflight(900, 7, 0, k_dev_vda, blk_req_write);
    blk_rq_reissue(&cur, &requeued);
    assert_true(cur.issue_ns == 900, "a requeue takes the new issue time");
    assert_true(cur.queue_ns == 7, "a requeue takes the new queue wait");
    assert_true(cur.dev == k_dev_vda && cur.kind == blk_req_write,
                "a requeue keeps device and kind");
    assert_true(cur.bytes_done == 0, "a requeue without partial completions has no bytes done");

    // SCSI completes the good part of a request, then requeues the rest.
    cur = inflight(100, 5, 1024, k_dev_vda, blk_req_write);
    blk_rq_reissue(&cur, &requeued);
    assert_true(cur.issue_ns == 900, "the requeued rest takes the new issue time");
    assert_true(cur.bytes_done == 1024, "the requeued rest keeps the bytes already completed");

    // The request struct was reused after a completion this program missed:
    // nothing of the stale entry may reach the new request.
    cur = inflight(100, 5, 1024, k_dev_vdb, blk_req_read);
    blk_rq_reissue(&cur, &requeued);
    assert_true(cur.dev == k_dev_vda, "a reused request struct takes the new device");
    assert_true(cur.kind == blk_req_write, "a reused request struct takes the new kind");
    assert_true(cur.bytes_done == 0, "a stale entry of another device leaks no bytes");

    cur = inflight(100, 5, 1024, k_dev_vda, blk_req_read);
    blk_rq_reissue(&cur, &requeued);
    assert_true(cur.bytes_done == 0, "a stale entry of another kind leaks no bytes");
}

// The per-device in-flight count as blk_io.c keeps it, over two disks.
struct dev_counts {
    long long vda;
    long long vdb;
};

static long long *dev_count(struct dev_counts *const c, const u32 dev) {
    return dev == k_dev_vda ? &c->vda : &c->vdb;
}

// blk_on_issue on an entry that is still present.
static void reissue_counted(struct dev_counts *const c,
                            struct blk_rq_inflight *const cur,
                            const struct blk_rq_inflight *const issued) {
    const u32 prev_dev = blk_rq_reissue(cur, issued);
    if (prev_dev != issued->dev) {
        (*dev_count(c, prev_dev))--;
        (*dev_count(c, issued->dev))++;
    }
}

static void test_reissue_moves_the_count(void) {
    struct dev_counts counts = {};

    // Issued on vda; its completion is missed, so the entry stays.
    struct blk_rq_inflight cur = inflight(100, 0, 0, k_dev_vda, blk_req_write);
    (*dev_count(&counts, cur.dev))++;

    // The tag set is shared by both disks: the same request struct is issued
    // for vdb, then completes.
    const struct blk_rq_inflight on_vdb = inflight(900, 0, 0, k_dev_vdb, blk_req_write);
    struct blk_rq_inflight probe = cur;
    assert_true(blk_rq_reissue(&probe, &on_vdb) == k_dev_vda,
                "a reissue returns the device the entry was counted on");
    reissue_counted(&counts, &cur, &on_vdb);
    (*dev_count(&counts, cur.dev))--;

    assert_true(counts.vda == 0, "a reused request struct releases the stale issue's disk");
    assert_true(counts.vdb == 0, "the other disk's completion does not take it below zero");

    // A requeue on the same disk is not a new request in flight.
    counts = (struct dev_counts){};
    cur = inflight(100, 0, 0, k_dev_vda, blk_req_write);
    (*dev_count(&counts, cur.dev))++;
    const struct blk_rq_inflight requeued = inflight(900, 0, 0, k_dev_vda, blk_req_write);
    reissue_counted(&counts, &cur, &requeued);
    assert_true(counts.vda == 1 && counts.vdb == 0, "a requeue leaves the count alone");
    (*dev_count(&counts, cur.dev))--;
    assert_true(counts.vda == 0, "the requeued request's completion brings it back to zero");
}

struct req_op_case {
    const char *name;
    u32 value;
    enum blk_req_kind kind;
};

// A kernel's enum req_op (or req_opf), copied from
// `bpftool btf dump file /sys/kernel/btf/vmlinux format c` on that kernel,
// and the value CO-RE resolves REQ_OP_ZONE_APPEND to there. Every operation
// the kernel defines is listed, so an operation that changes kind shows up.
struct req_op_table {
    const char *kernel;
    u32 zone_append;
    const struct req_op_case *ops;
    unsigned int n_ops;
};

// enum req_opf in bpf/bpfcore/vmlinux_amd64.h.
static const struct req_op_case bpfcore_ops[] = {
    {"REQ_OP_READ", 0, blk_req_read},
    {"REQ_OP_WRITE", 1, blk_req_write},
    {"REQ_OP_FLUSH", 2, blk_req_flush},
    {"REQ_OP_DISCARD", 3, blk_req_discard},
    {"REQ_OP_SECURE_ERASE", 5, blk_req_discard},
    {"REQ_OP_WRITE_SAME", 7, blk_req_ignore},
    {"REQ_OP_WRITE_ZEROES", 9, blk_req_write},
    {"REQ_OP_ZONE_OPEN", 10, blk_req_ignore},
    {"REQ_OP_ZONE_CLOSE", 11, blk_req_ignore},
    {"REQ_OP_ZONE_FINISH", 12, blk_req_ignore},
    {"REQ_OP_ZONE_APPEND", 13, blk_req_write},
    {"REQ_OP_ZONE_RESET", 15, blk_req_ignore},
    {"REQ_OP_ZONE_RESET_ALL", 17, blk_req_ignore},
    {"REQ_OP_DRV_IN", 34, blk_req_ignore},
    {"REQ_OP_DRV_OUT", 35, blk_req_ignore},
};

// enum req_op of Rocky Linux 9, 5.14.0-687.
static const struct req_op_case rocky_687_ops[] = {
    {"REQ_OP_READ", 0, blk_req_read},
    {"REQ_OP_WRITE", 1, blk_req_write},
    {"REQ_OP_FLUSH", 2, blk_req_flush},
    {"REQ_OP_DISCARD", 3, blk_req_discard},
    {"REQ_OP_SECURE_ERASE", 5, blk_req_discard},
    {"REQ_OP_ZONE_APPEND", 7, blk_req_write},
    {"REQ_OP_WRITE_ZEROES", 9, blk_req_write},
    {"REQ_OP_ZONE_OPEN", 10, blk_req_ignore},
    {"REQ_OP_ZONE_CLOSE", 11, blk_req_ignore},
    {"REQ_OP_ZONE_FINISH", 13, blk_req_ignore},
    {"REQ_OP_ZONE_RESET", 15, blk_req_ignore},
    {"REQ_OP_ZONE_RESET_ALL", 17, blk_req_ignore},
    {"REQ_OP_DRV_IN", 34, blk_req_ignore},
    {"REQ_OP_DRV_OUT", 35, blk_req_ignore},
};

// enum req_op of CentOS Stream 9, 5.14.0-749 (MicroShift lab).
static const struct req_op_case cs9_749_ops[] = {
    {"REQ_OP_READ", 0, blk_req_read},
    {"REQ_OP_WRITE", 1, blk_req_write},
    {"REQ_OP_FLUSH", 2, blk_req_flush},
    {"REQ_OP_DISCARD", 3, blk_req_discard},
    {"REQ_OP_SECURE_ERASE", 5, blk_req_discard},
    {"REQ_OP_ZONE_APPEND", 7, blk_req_write},
    {"REQ_OP_WRITE_ZEROES", 9, blk_req_write},
    {"REQ_OP_ZONE_OPEN", 11, blk_req_ignore},
    {"REQ_OP_ZONE_CLOSE", 13, blk_req_ignore},
    {"REQ_OP_ZONE_FINISH", 15, blk_req_ignore},
    {"REQ_OP_ZONE_RESET", 17, blk_req_ignore},
    {"REQ_OP_ZONE_RESET_ALL", 19, blk_req_ignore},
    {"REQ_OP_DRV_IN", 34, blk_req_ignore},
    {"REQ_OP_DRV_OUT", 35, blk_req_ignore},
};

static const struct req_op_table req_op_tables[] = {
    {"bpfcore vmlinux", 13, bpfcore_ops, sizeof(bpfcore_ops) / sizeof(bpfcore_ops[0])},
    {"rocky 5.14.0-687", 7, rocky_687_ops, sizeof(rocky_687_ops) / sizeof(rocky_687_ops[0])},
    {"cs9 5.14.0-749", 7, cs9_749_ops, sizeof(cs9_749_ops) / sizeof(cs9_749_ops[0])},
};

enum {
    k_req_preflush = 1u << 18, // __REQ_PREFLUSH on all three kernels
    k_req_fua = 1u << 17,      // __REQ_FUA on all three kernels
};

static void test_req_op_tables(void) {
    char message[160];
    for (unsigned int t = 0; t < sizeof(req_op_tables) / sizeof(req_op_tables[0]); t++) {
        const struct req_op_table *const table = &req_op_tables[t];
        for (unsigned int i = 0; i < table->n_ops; i++) {
            const struct req_op_case *const c = &table->ops[i];
            snprintf(message, sizeof(message), "%s: %s (%u)", table->kernel, c->name, c->value);
            assert_true(blk_kind_from_cmd_flags(c->value, table->zone_append) == c->kind, message);

            snprintf(message,
                     sizeof(message),
                     "%s: %s (%u) with PREFLUSH|FUA",
                     table->kernel,
                     c->name,
                     c->value);
            assert_true(blk_kind_from_cmd_flags(c->value | k_req_preflush | k_req_fua,
                                                table->zone_append) == c->kind,
                        message);
        }
    }
}

static void test_kernel_without_zone_append(void) {
    assert_true(blk_kind_from_cmd_flags(7, k_req_op_absent) == blk_req_ignore,
                "op 7 is not a write on a kernel without REQ_OP_ZONE_APPEND");
    assert_true(blk_kind_from_cmd_flags(13, k_req_op_absent) == blk_req_ignore,
                "op 13 is not a write on a kernel without REQ_OP_ZONE_APPEND");
}

struct rwbs_case {
    const char *rwbs;
    enum blk_req_kind kind;
    const char *what;
};

// Strings blk_fill_rwbs() builds: the REQ_PREFLUSH 'F', the operation's
// letter, then the FUA 'F' and the 'A', 'S', 'M' flag letters.
static const struct rwbs_case rwbs_cases[] = {
    {"R", blk_req_read, "a read"},
    {"RA", blk_req_read, "a readahead"},
    {"RSM", blk_req_read, "a sync metadata read"},
    {"W", blk_req_write, "a write"},
    {"WS", blk_req_write, "a sync write"},
    {"WFS", blk_req_write, "a FUA write"},
    {"FW", blk_req_write, "a write with a preflush"},
    {"FWFS", blk_req_write, "a FUA write with a preflush"},
    {"F", blk_req_flush, "a flush"},
    {"FF", blk_req_flush, "the flush machinery's flush request (REQ_OP_FLUSH|REQ_PREFLUSH)"},
    {"FFS", blk_req_flush, "a sync flush request"},
    {"D", blk_req_discard, "a discard"},
    {"DE", blk_req_discard, "a secure erase"},
    {"DS", blk_req_discard, "a sync discard"},
    {"N", blk_req_ignore, "an operation without a letter of its own"},
    {"", blk_req_ignore, "an empty rwbs"},
};

static void test_rwbs(void) {
    char message[160];
    for (unsigned int i = 0; i < sizeof(rwbs_cases) / sizeof(rwbs_cases[0]); i++) {
        const struct rwbs_case *const c = &rwbs_cases[i];
        const char rwbs0 = c->rwbs[0];
        const char rwbs1 = rwbs0 ? c->rwbs[1] : 0;
        snprintf(message, sizeof(message), "rwbs \"%s\" is %s", c->rwbs, c->what);
        assert_true(blk_kind_from_rwbs(rwbs0, rwbs1) == c->kind, message);
    }
}

enum {
    k_emit_read_write = (1 << blk_req_read) | (1 << blk_req_write),
    k_emit_flush = 1 << blk_req_flush,
    k_emit_discard = 1 << blk_req_discard,
};

static void test_kind_emitted(void) {
    assert_true(blk_kind_emitted(k_emit_read_write, blk_req_read), "reads reach userspace");
    assert_true(blk_kind_emitted(k_emit_read_write, blk_req_write), "writes reach userspace");
    assert_true(!blk_kind_emitted(k_emit_read_write, blk_req_flush),
                "flushes do not reach userspace without their metric");
    assert_true(!blk_kind_emitted(k_emit_read_write, blk_req_discard),
                "discards do not reach userspace without their metric");
    assert_true(blk_kind_emitted(k_emit_flush, blk_req_flush), "flushes reach userspace");
    assert_true(!blk_kind_emitted(k_emit_flush, blk_req_write),
                "writes do not reach userspace with only the flush metric");
    assert_true(blk_kind_emitted(k_emit_discard, blk_req_discard), "discards reach userspace");
    assert_true(
        !blk_kind_emitted(k_emit_read_write | k_emit_flush | k_emit_discard, blk_req_ignore),
        "an ignored request never reaches userspace");
    assert_true(!blk_kind_emitted(0, blk_req_read), "no kind reaches userspace with no metric");
}

static void test_agg_key(void) {
    const struct blk_rq_inflight rq = inflight(1000, 0, 0, k_dev_vda, blk_req_flush);

    const struct blk_agg_key ok = blk_agg_key_of(&rq, 0);
    assert_true(ok.dev == k_dev_vda && ok.kind == blk_req_flush && ok.err == 0 && ok.part_dev == 0,
                "a successful request's key names its device and kind, with no errno");

    const struct blk_agg_key failed = blk_agg_key_of(&rq, -5);
    assert_true(failed.err == 5, "a failed request's key holds its errno, positive (EIO)");
    assert_true(blk_agg_err(-528) == 528, "a kernel-internal errno (EJUKEBOX) fits the key");
    assert_true(blk_agg_err(-95) == 95, "EOPNOTSUPP");
    assert_true(blk_agg_err(-70000) == 0xffff, "an out-of-range error is clamped, not wrapped");
    assert_true(blk_agg_err(0) == 0, "no error");

    const struct blk_agg_key again = blk_agg_key_of(&rq, 0);
    assert_true(__builtin_memcmp(&ok, &again, sizeof(ok)) == 0,
                "equal requests build byte-identical keys: the padding is zeroed");
    assert_true(sizeof(struct blk_agg_key) == 16, "the aggregation key is 16 bytes");

    struct blk_rq_inflight on_partition = rq;
    on_partition.part_dev = k_dev_vdb;
    const struct blk_agg_key with_part = blk_agg_key_of(&on_partition, 0);
    assert_true(with_part.part_dev == k_dev_vdb,
                "the in-flight entry's partition carries into the aggregation key");
}

// The pod counters' key (storage_block_pod): the cgroup the in-flight entry
// was charged to at its issue, with its device, partition and direction.
static void test_cg_key(void) {
    enum { k_pod_cgid = 72286 }; // S0-d: the io-xfs container's /container leaf
    struct blk_rq_inflight rq = inflight(1000, 0, 4096, k_dev_vda, blk_req_write);
    rq.cgid = k_pod_cgid;

    const struct blk_cg_key key = blk_cg_key_of(&rq);
    assert_true(key.cgid == k_pod_cgid && key.dev == k_dev_vda && key.part_dev == 0 &&
                    key.kind == blk_req_write,
                "the key names the cgroup, device and direction of the request");

    const struct blk_cg_key again = blk_cg_key_of(&rq);
    assert_true(__builtin_memcmp(&key, &again, sizeof(key)) == 0,
                "equal requests build byte-identical keys: the padding is zeroed");
    assert_true(sizeof(struct blk_cg_key) == 24, "the pod key is 24 bytes");

    rq.part_dev = k_dev_vdb;
    assert_true(blk_cg_key_of(&rq).part_dev == k_dev_vdb,
                "the partition, when selected, carries into the pod key");

    rq.cgid = 0;
    assert_true(blk_cg_key_of(&rq).cgid == 0,
                "I/O charged to no cgroup is counted under id 0, not dropped");
}

// operation_time counts from the accounting start when the request has a
// valid one (diskstats fields 7 and 11), else from its issue.
static void test_op_time(void) {
    assert_true(blk_op_time_ns(500, 0) == 500, "no valid start: issue -> completion");
    assert_true(blk_op_time_ns(500, 200) == 700, "a valid start: start -> completion");
    assert_true(blk_op_time_ns(500, blk_queue_ns(1500, 1500)) == 501,
                "a start equal to the issue adds the 1 ns blk_queue_ns records it as");
}

// A request struct reused after a missed completion must not lend the stale
// entry's cgroup to the new request; a bio pointer reused likewise.
static void test_reissue_replaces_the_cgroup(void) {
    struct blk_rq_inflight cur = inflight(100, 5, 1024, k_dev_vda, blk_req_write);
    cur.cgid = 111;
    struct blk_rq_inflight issued = inflight(900, 7, 0, k_dev_vda, blk_req_write);
    issued.cgid = 222;
    blk_rq_reissue(&cur, &issued);
    assert_true(cur.cgid == 222, "a requeue or a reused request takes the new issue's cgroup");

    cur.cgid = 111;
    blk_bio_requeue(&cur, &issued);
    assert_true(cur.cgid == 222, "a reused bio pointer takes the new bio's cgroup");
}

static void test_part_dev(void) {
    assert_true(blk_part_dev(k_dev_vda, k_dev_vda) == 0,
                "a bio or rq->part naming the whole disk is not a partition");
    assert_true(blk_part_dev(0, k_dev_vda) == 0, "an unresolved partition stays 0");
    assert_true(blk_part_dev(k_dev_vdb, k_dev_vda) == k_dev_vdb,
                "a partition distinct from the disk is reported as-is");
}

static void test_read_write(void) {
    assert_true(blk_kind_is_read_write(blk_req_read), "a read is a read or write");
    assert_true(blk_kind_is_read_write(blk_req_write), "a write is a read or write");
    assert_true(!blk_kind_is_read_write(blk_req_flush), "a flush is neither");
    assert_true(!blk_kind_is_read_write(blk_req_discard), "a discard is neither");
    assert_true(!blk_kind_is_read_write(blk_req_ignore), "an ignored request is neither");
}

enum { k_io_stat = 1U << 8, k_flush_seq = 1U << 0, k_other_flag = 1U << 5 };

static void test_queue_start(void) {
    const u64 start = 1000;
    assert_true(blk_start_if_valid(k_io_stat, k_io_stat, k_flush_seq, start) == start,
                "RQF_IO_STAT set, no flush sequence: the start is fresh");
    assert_true(blk_start_if_valid(k_io_stat | k_other_flag, k_io_stat, k_flush_seq, start) ==
                    start,
                "unrelated flags do not matter");
    assert_true(blk_start_if_valid(0, k_io_stat, k_flush_seq, start) == 0,
                "RQF_IO_STAT clear (queue/iostats=0) with a nonzero start: no sample");
    assert_true(blk_start_if_valid(k_other_flag, k_io_stat, k_flush_seq, start) == 0,
                "other flags without RQF_IO_STAT: no sample");
    assert_true(blk_start_if_valid(k_io_stat | k_flush_seq, k_io_stat, k_flush_seq, start) == 0,
                "RQF_IO_STAT and RQF_FLUSH_SEQ both set (flush-machine write): no sample");
    assert_true(blk_start_if_valid(k_io_stat, 0, 0, start) == 0,
                "enum rqf_flags absent from BTF (mask 0): no queue time");
    assert_true(blk_start_if_valid(k_io_stat, k_io_stat, 0, start) == start,
                "an absent RQF_FLUSH_SEQ does not hide a valid start");
}

static void test_queue_ns(void) {
    assert_true(blk_queue_ns(1000, 1500) == 500, "queue time is issue minus start");
    assert_true(blk_queue_ns(0, 1500) == 0, "no valid start: no queue time");
    assert_true(blk_queue_ns(2000, 1500) == 0, "a start after the issue: no sample");
    assert_true(blk_queue_ns(1500, 1500) == 1, "a zero interval is recorded as 1 ns, not as none");
}

// Bio shapes observed at block_bio_queue on dm-linear, dm-thin and md (S0-b,
// 5.14.0-749: REQ_OP_WRITE 1, REQ_OP_DISCARD 3, __REQ_FUA 17, __REQ_PREFLUSH
// 18).
static void test_bio_kind(void) {
    const u32 za = 7;
    assert_true(blk_kind_from_bio(k_req_op_write | k_req_preflush, 0, za, k_req_preflush) ==
                    blk_req_flush,
                "an empty PREFLUSH write bio (blkdev_issue_flush) is a flush");
    assert_true(
        blk_kind_from_bio(k_req_op_write | k_req_preflush | k_req_fua, 4096, za, k_req_preflush) ==
            blk_req_write,
        "a PREFLUSH|FUA bio with data (a journal commit) is a write");
    assert_true(blk_kind_from_bio(k_req_op_write | k_req_preflush, 512, za, k_req_preflush) ==
                    blk_req_write,
                "a PREFLUSH bio with data is a write");
    assert_true(blk_kind_from_bio(k_req_op_write, 4096, za, k_req_preflush) == blk_req_write,
                "a data write bio is a write");
    assert_true(blk_kind_from_bio(k_req_op_write | k_req_fua, 4096, za, k_req_preflush) ==
                    blk_req_write,
                "a FUA write bio is a write");
    assert_true(blk_kind_from_bio(k_req_op_write, 0, za, k_req_preflush) == blk_req_write,
                "an empty write without PREFLUSH is not taken for a flush");
    assert_true(blk_kind_from_bio(k_req_op_read, 4096, za, k_req_preflush) == blk_req_read,
                "a read bio is a read");
    assert_true(blk_kind_from_bio(k_req_op_read, 0, za, k_req_preflush) == blk_req_read,
                "an empty read is not a flush");
    assert_true(blk_kind_from_bio(k_req_op_discard, 64 << 20, za, k_req_preflush) ==
                    blk_req_discard,
                "a discard bio is a discard");
    assert_true(blk_kind_from_bio(k_req_op_secure_erase, 4096, za, k_req_preflush) ==
                    blk_req_discard,
                "a secure erase bio is a discard");
    assert_true(blk_kind_from_bio(k_req_op_write_zeroes, 4096, za, k_req_preflush) == blk_req_write,
                "a write-zeroes bio is a write");
    assert_true(blk_kind_from_bio(za, 4096, za, k_req_preflush) == blk_req_write,
                "a zone append bio is a write");
    assert_true(blk_kind_from_bio(k_req_op_flush, 0, za, k_req_preflush) == blk_req_flush,
                "REQ_OP_FLUSH, should a bio ever carry it, is a flush");
    assert_true(blk_kind_from_bio(11, 0, za, k_req_preflush) == blk_req_ignore,
                "a zone management bio is ignored");

    // A kernel whose BTF does not name __REQ_PREFLUSH.
    assert_true(blk_kind_from_bio(k_req_op_write | k_req_preflush, 0, za, 0) == blk_req_flush,
                "without the PREFLUSH bit, an empty write is a flush");
    assert_true(blk_kind_from_bio(k_req_op_write, 0, za, 0) == blk_req_flush,
                "without the PREFLUSH bit, any empty write is a flush");
    assert_true(blk_kind_from_bio(k_req_op_write | k_req_preflush, 4096, za, 0) == blk_req_write,
                "without the PREFLUSH bit, a write with data is a write");
    assert_true(blk_kind_from_bio(k_req_op_discard, 0, za, 0) == blk_req_discard,
                "without the PREFLUSH bit, a discard is still a discard");
}

// A bio pointer queued again while its entry is present is another bio in a
// reused struct: unlike a requeued request, it inherits nothing.
static void test_bio_requeue_replaces_the_entry(void) {
    struct blk_rq_inflight cur = inflight(100, 0, 1 << 20, k_dev_vda, blk_req_write);
    const struct blk_rq_inflight queued = inflight(900, 0, 4096, k_dev_vda, blk_req_write);
    assert_true(blk_bio_requeue(&cur, &queued) == k_dev_vda,
                "the entry was counted on the same device");
    assert_true(cur.issue_ns == 900, "the new bio is timed from its own queueing");
    assert_true(cur.bytes_done == 4096,
                "the new bio's bytes replace the stale ones, even on the same device and kind");

    cur = inflight(100, 0, 1 << 20, k_dev_vdb, blk_req_read);
    assert_true(blk_bio_requeue(&cur, &queued) == k_dev_vdb,
                "the device the stale entry was counted on is returned");
    assert_true(cur.dev == k_dev_vda && cur.kind == blk_req_write && cur.bytes_done == 4096,
                "a reused bio struct takes the new device, kind and bytes");
}

enum {
    k_major_dm = 253,
    k_major_md = 9,
    k_major_blkext = 259,
    k_major_virtblk = 252,
    k_dev_md127 = (k_major_md << 20) | 127,
    k_dev_md127p1 = (k_major_blkext << 20) | 2,
};

static void test_vol_major(void) {
    const u32 none[k_blk_vol_majors] = {};
    assert_true(!blk_vol_major_match(none, k_major_dm), "no tracked volume: no major matches");
    assert_true(!blk_vol_major_match(none, 0),
                "major 0, an unset slot or a failed read, never matches");

    const u32 dm_md[k_blk_vol_majors] = {k_major_dm, k_major_md, 0};
    assert_true(blk_vol_major_match(dm_md, k_major_dm), "the device-mapper major matches");
    assert_true(blk_vol_major_match(dm_md, k_major_md), "the md major matches");
    assert_true(!blk_vol_major_match(dm_md, k_major_virtblk),
                "a request-based disk's major is rejected before any lookup");
    assert_true(!blk_vol_major_match(dm_md, 7), "the loop major is rejected");
    assert_true(!blk_vol_major_match(dm_md, k_major_blkext),
                "the extended block major (NVMe disks, partitions) is rejected");
    assert_true(!blk_vol_major_match(dm_md, 0), "major 0 does not match the unused slot");

    const u32 last[k_blk_vol_majors] = {0, 0, 254};
    assert_true(blk_vol_major_match(last, 254), "every slot is compared");
}

// A bio submitted to a partition of an md array: its block_device is the
// partition, 259:2 (the extended block major), while its gendisk is the
// array, 9:127 (S0-b). The filter and the lookup key come from the gendisk,
// the partition from the block_device.
static void test_bio_md_partition(void) {
    const u32 majors[k_blk_vol_majors] = {k_major_dm, k_major_md, 0};
    assert_true(blk_disk_devt(k_major_md, 127) == k_dev_md127,
                "the lookup key is MKDEV(gendisk major, first_minor)");
    assert_true(blk_vol_major_match(majors, k_major_md),
                "the gendisk's major passes the filter for a bio to a partition");
    assert_true(!blk_vol_major_match(majors, k_dev_md127p1 >> k_minorbits),
                "the major of the partition's own dev_t would be rejected");
    assert_true(blk_part_dev(k_dev_md127p1, k_dev_md127) == k_dev_md127p1,
                "the bio's block_device names the partition");
    assert_true(blk_part_dev(k_dev_md127, k_dev_md127) == 0,
                "a bio to the whole array has no partition");
    // blk_bio.c passes the disk itself as pdev when obi.disk.partition is not
    // selected.
    assert_true(blk_part_dev(k_dev_md127, k_dev_md127) == 0,
                "the partition is omitted when it is not selected");
}

int main(void) {
    test_status_to_errno();
    test_final_chunk();
    test_complete_error();
    test_requeue_overwrites_the_entry();
    test_reissue_moves_the_count();
    test_req_op_tables();
    test_kernel_without_zone_append();
    test_rwbs();
    test_kind_emitted();
    test_agg_key();
    test_part_dev();
    test_read_write();
    test_queue_start();
    test_queue_ns();
    test_bio_kind();
    test_bio_requeue_replaces_the_entry();
    test_vol_major();
    test_bio_md_partition();
    test_cg_key();
    test_op_time();
    test_reissue_replaces_the_cgroup();

    if (failed_assertions != 0) {
        printf("%u failed assertions\n", failed_assertions);
        return 1;
    }

    return 0;
}
