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

static const u64 bounds_ns[] = {50000, 100000, 250000};
static const u32 bounds_len = sizeof(bounds_ns) / sizeof(bounds_ns[0]);

static void test_latency_bucket_is_upper_inclusive(void) {
    assert_true(disk_latency_bucket(bounds_ns, bounds_len, 0) == 0,
                "zero goes to the first bucket");
    assert_true(disk_latency_bucket(bounds_ns, bounds_len, 50000) == 0,
                "a value equal to the first bound stays in the first bucket");
    assert_true(disk_latency_bucket(bounds_ns, bounds_len, 50001) == 1,
                "a value just above a bound goes to the next bucket");
    assert_true(disk_latency_bucket(bounds_ns, bounds_len, 250000) == 2,
                "a value equal to the last bound stays in the last bounded bucket");
    assert_true(disk_latency_bucket(bounds_ns, bounds_len, 250001) == bounds_len,
                "a value above the last bound goes to the overflow bucket");
}

static void test_latency_bucket_without_bounds(void) {
    assert_true(disk_latency_bucket(bounds_ns, 0, 1000000000) == 0,
                "without bounds every value goes to the single bucket");
}

static void test_latency_bucket_never_exceeds_the_bucket_array(void) {
    u64 max_bounds[k_disk_latency_max_bounds];
    for (u32 i = 0; i < k_disk_latency_max_bounds; i++) {
        max_bounds[i] = i + 1;
    }
    assert_true(disk_latency_bucket(max_bounds, k_disk_latency_max_bounds, ~0ULL) ==
                    k_disk_latency_max_buckets - 1,
                "the overflow bucket of a full bounds array is the last histogram bucket");
    assert_true(disk_latency_bucket(max_bounds, k_disk_latency_max_bounds + 5, ~0ULL) ==
                    k_disk_latency_max_buckets - 1,
                "a bounds_len larger than the array is capped");
}

static void test_final_completion(void) {
    assert_true(disk_rq_final_completion(4096, 4096, 0), "completing all remaining bytes is final");
    assert_true(!disk_rq_final_completion(4096, 8192, 0), "a partial completion is not final");
    assert_true(disk_rq_final_completion(0, 0, 0), "a zero-byte request (flush) is final");
    assert_true(disk_rq_final_completion(4096, 8192, 10), "a failed completion is final");
}

static void test_status_code(void) {
    // blk_status_t since Linux 5.16: BLK_STS_IOERR is 10
    assert_true(disk_status_code(10, true) == 10, "a blk_status_t is kept as is");
    assert_true(disk_status_code(0, true) == 0, "BLK_STS_OK is success");
    // negative errno before Linux 5.16, sign-extended in the raw tracepoint argument
    assert_true(disk_status_code((u64)(s64)-5, false) == 5, "-EIO becomes errno 5");
    assert_true(disk_status_code(0, false) == 0, "errno 0 is success");
}

static void test_op_from_req_op(void) {
    assert_true(disk_op_from_req_op(0) == disk_op_read, "REQ_OP_READ is a read");
    assert_true(disk_op_from_req_op(1) == disk_op_write, "REQ_OP_WRITE is a write");
    assert_true(disk_op_from_req_op(2) == disk_op_flush, "REQ_OP_FLUSH is a flush");
    assert_true(disk_op_from_req_op(3) == disk_op_discard, "REQ_OP_DISCARD is a discard");
    assert_true(disk_op_from_req_op(5) == disk_op_discard, "REQ_OP_SECURE_ERASE is a discard");
    assert_true(disk_op_from_req_op(9) == disk_op_unknown, "REQ_OP_WRITE_ZEROES is not measured");
    assert_true(disk_op_from_req_op(34) == disk_op_unknown,
                "driver private operations are not measured");
}

static void test_queue_ns(void) {
    assert_true(disk_queue_ns(1000, 1500) == 500, "the wait is the time from allocation to issue");
    assert_true(disk_queue_ns(1500, 1500) == 0,
                "a request issued as soon as allocated did not wait");
    assert_true(disk_queue_ns(0, 1500) == k_disk_queue_unknown,
                "the wait is unknown when the kernel didn't record the allocation time");
    assert_true(disk_queue_ns(2000, 1500) == k_disk_queue_unknown,
                "an allocation time after the issue is not trusted");
}

static void test_fs_sync_status(void) {
    assert_true(fs_sync_status(0) == 0, "a successful sync has no status");
    assert_true(fs_sync_status(-5) == 5, "-EIO becomes errno 5");
    assert_true(fs_sync_status(-22) == 22, "-EINVAL becomes errno 22");
    assert_true(!fs_sync_attempted(-9), "an invalid file descriptor is not a file sync");
    assert_true(fs_sync_attempted(-22), "a file that can't be synced is a failed file sync");
    assert_true(fs_sync_attempted(0), "a successful sync is a file sync");
}

int main(void) {
    test_latency_bucket_is_upper_inclusive();
    test_latency_bucket_without_bounds();
    test_latency_bucket_never_exceeds_the_bucket_array();
    test_final_completion();
    test_status_code();
    test_op_from_req_op();
    test_queue_ns();
    test_fs_sync_status();

    if (failed_assertions) {
        printf("%u assertion(s) failed\n", failed_assertions);
        return 1;
    }
    return 0;
}
