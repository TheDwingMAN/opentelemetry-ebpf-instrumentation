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
    assert_true(blk_rq_final_chunk(4096, 4096, k_blk_sts_ok),
                "a completion covering the whole request ends it");
    assert_true(!blk_rq_final_chunk(1024, 4096, k_blk_sts_ok),
                "a partial completion (SCSI good_bytes) does not end the request");
    assert_true(blk_rq_final_chunk(3072, 3072, k_blk_sts_ok),
                "the chunk covering what is left ends the request");
    assert_true(blk_rq_final_chunk(0, 0, k_blk_sts_ok), "a flush, which carries no data, ends");
    assert_true(blk_rq_final_chunk(512, 4096, k_blk_sts_medium),
                "a failed chunk ends the request even when data is left");
    assert_true(blk_rq_final_chunk(8192, 4096, k_blk_sts_ok),
                "a completion larger than what is left ends the request");
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

int main(void) {
    test_status_to_errno();
    test_final_chunk();
    test_requeue_overwrites_the_entry();
    test_reissue_moves_the_count();
    test_req_op_tables();
    test_kernel_without_zone_append();
    test_rwbs();
    test_kind_emitted();

    if (failed_assertions != 0) {
        printf("%u failed assertions\n", failed_assertions);
        return 1;
    }

    return 0;
}
