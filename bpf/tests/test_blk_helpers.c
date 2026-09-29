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
    {"REQ_OP_FLUSH", 2, blk_req_write},
    {"REQ_OP_DISCARD", 3, blk_req_ignore},
    {"REQ_OP_SECURE_ERASE", 5, blk_req_ignore},
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
    {"REQ_OP_FLUSH", 2, blk_req_write},
    {"REQ_OP_DISCARD", 3, blk_req_ignore},
    {"REQ_OP_SECURE_ERASE", 5, blk_req_ignore},
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
    {"REQ_OP_FLUSH", 2, blk_req_write},
    {"REQ_OP_DISCARD", 3, blk_req_ignore},
    {"REQ_OP_SECURE_ERASE", 5, blk_req_ignore},
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

static void test_rwbs(void) {
    assert_true(blk_kind_from_rwbs0('R') == blk_req_read, "rwbs R is a read");
    assert_true(blk_kind_from_rwbs0('W') == blk_req_write, "rwbs W is a write");
    assert_true(blk_kind_from_rwbs0('F') == blk_req_write, "rwbs F is a write");
    assert_true(blk_kind_from_rwbs0('D') == blk_req_ignore, "rwbs D (discard) is ignored");
    assert_true(blk_kind_from_rwbs0('N') == blk_req_ignore, "rwbs N (other operation) is ignored");
}

int main(void) {
    test_status_to_errno();
    test_final_chunk();
    test_requeue_overwrites_the_entry();
    test_req_op_tables();
    test_kernel_without_zone_append();
    test_rwbs();

    if (failed_assertions != 0) {
        printf("%u failed assertions\n", failed_assertions);
        return 1;
    }

    return 0;
}
