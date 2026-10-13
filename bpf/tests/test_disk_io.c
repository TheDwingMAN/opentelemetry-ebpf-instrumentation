// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Run from repo root:
//   make -C bpf/tests test_disk_io && bpf/tests/test_disk_io
// Run from bpf/tests:
//   make test_disk_io && ./test_disk_io

#include <stdbool.h>
#include <stdio.h>

#include <statsolly/disk_io.h>

static unsigned int failed_assertions;

static void assert_true(bool condition, const char *message) {
    if (condition) {
        printf("PASS: %s\n", message);
        return;
    }

    failed_assertions++;
    printf("FAIL: %s\n", message);
}

enum { k_bound_step_ns = 50000 };

static void test_latency_bucket_is_upper_inclusive(void) {
    u64 bounds_ns[k_disk_latency_bounds];
    for (u32 i = 0; i < k_disk_latency_bounds; i++) {
        bounds_ns[i] = (i + 1) * k_bound_step_ns;
    }
    const u64 last_bound_ns = bounds_ns[k_disk_latency_bounds - 1];

    assert_true(disk_latency_bucket(bounds_ns, 0) == 0, "zero goes to the first bucket");
    assert_true(disk_latency_bucket(bounds_ns, k_bound_step_ns) == 0,
                "a value equal to the first bound stays in the first bucket");
    assert_true(disk_latency_bucket(bounds_ns, k_bound_step_ns + 1) == 1,
                "a value just above a bound goes to the next bucket");
    assert_true(disk_latency_bucket(bounds_ns, last_bound_ns) == k_disk_latency_bounds - 1,
                "a value equal to the last bound stays in the last bounded bucket");
    assert_true(disk_latency_bucket(bounds_ns, last_bound_ns + 1) == k_disk_latency_buckets - 1,
                "a value above the last bound goes to the overflow bucket, the last one");
    assert_true(disk_latency_bucket(bounds_ns, ~0ULL) == k_disk_latency_buckets - 1,
                "the largest value goes to the overflow bucket");
}

static void test_op_from_req_op(void) {
    assert_true(disk_op_from_req_op(k_req_op_read) == disk_op_read, "REQ_OP_READ is a read");
    assert_true(disk_op_from_req_op(k_req_op_write) == disk_op_write, "REQ_OP_WRITE is a write");
    assert_true(disk_op_from_req_op(k_req_op_write_zeroes) == disk_op_write,
                "REQ_OP_WRITE_ZEROES is a write");
    assert_true(disk_op_from_req_op(2) == disk_op_unknown, "REQ_OP_FLUSH is not measured");
    assert_true(disk_op_from_req_op(3) == disk_op_unknown, "REQ_OP_DISCARD is not measured");
    assert_true(disk_op_from_req_op(7) == disk_op_unknown,
                "a zone append (6.1+) or WRITE_SAME (5.8) is not measured");
    assert_true(disk_op_from_req_op(34) == disk_op_unknown,
                "driver private operations (passthrough) are not measured");
}

static void test_final_completion(void) {
    assert_true(disk_rq_final_completion(4096, 4096), "completing all remaining bytes is final");
    assert_true(!disk_rq_final_completion(4096, 8192),
                "a partial completion is not final, even a failed one: the rest is retried or "
                "failed in another completion");
    assert_true(disk_rq_final_completion(0, 0),
                "the end of a request without bytes left is final, as at the end of a flush "
                "sequence");
}

static void test_status_code(void) {
    // a blk_status_t from Linux 5.16
    assert_true(disk_status_code(10, true) == 10, "BLK_STS_IOERR is status 10");
    assert_true(disk_status_code(0, true) == 0, "BLK_STS_OK is a success");
    // a negative int errno before, which the raw tracepoint argument holds zero-extended
    assert_true(disk_status_code((u32)-5, false) == 5, "-EIO is status 5");
    assert_true(disk_status_code((u64)-5, false) == 5, "a sign-extended -EIO is status 5 too");
    assert_true(disk_status_code(0, false) == 0, "errno 0 is a success");
    assert_true(disk_status_code((u32)-512, false) == k_status_other,
                "an errno that doesn't fit in a status, like ERESTARTSYS, is not a success");
}

static void test_fs_sync_attempted(void) {
    assert_true(!fs_sync_attempted(-9), "an invalid file descriptor is not a file sync");
    assert_true(!fs_sync_attempted(-22),
                "a file that can't be synced, such as a pipe, is not a file sync");
    assert_true(!fs_sync_attempted(-29),
                "a sync_file_range on a pipe, which fails with ESPIPE, is not a file sync");
    assert_true(fs_sync_attempted(-5), "a sync that failed with EIO is a failed file sync");
    assert_true(fs_sync_attempted(0), "a successful sync is a file sync");
}

static void test_sync_file_range_waits(void) {
    assert_true(!sync_file_range_waits(k_sync_file_range_write),
                "a SYNC_FILE_RANGE_WRITE hint doesn't wait for the writeback");
    assert_true(!sync_file_range_waits(0), "a call without flags doesn't wait");
    assert_true(sync_file_range_waits(k_sync_file_range_wait_before), "WAIT_BEFORE waits");
    assert_true(sync_file_range_waits(k_sync_file_range_wait_after), "WAIT_AFTER waits");
    assert_true(!sync_file_range_waits(0xfffffff8u), "bits above the three flags are not waits");
}

int main(void) {
    test_latency_bucket_is_upper_inclusive();
    test_op_from_req_op();
    test_final_completion();
    test_status_code();
    test_fs_sync_attempted();
    test_sync_file_range_waits();

    if (failed_assertions) {
        printf("%u assertion(s) failed\n", failed_assertions);
        return 1;
    }
    return 0;
}
