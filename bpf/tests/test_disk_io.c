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
    assert_true(disk_status_code((u64)(s64)-512, false) == k_status_other,
                "an errno that doesn't fit in a status is not reported as a success");
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

static void test_bio_op(void) {
    const u32 op_mask = 0xff;
    const u32 preflush = 1U << 18;
    assert_true(disk_bio_op(1, op_mask, preflush, 4096) == disk_op_write, "a write bio is a write");
    assert_true(disk_bio_op(1 | preflush, op_mask, preflush, 0) == disk_op_flush,
                "an empty write with the preflush flag is a flush");
    assert_true(disk_bio_op(1 | preflush, op_mask, preflush, 4096) == disk_op_write,
                "a write with data and the preflush flag is a write");
    assert_true(disk_bio_op(1, op_mask, preflush, 0) == disk_op_write,
                "an empty write without the preflush flag is a write");
    assert_true(disk_bio_op(0 | preflush, op_mask, preflush, 0) == disk_op_read,
                "the preflush flag only turns writes into flushes");
    assert_true(disk_bio_op(3, op_mask, preflush, 1 << 20) == disk_op_discard, "a discard bio");
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

static void test_rq_bytes(void) {
    assert_true(disk_rq_bytes(4096, 8) == 4096, "a request completed at once");
    assert_true(disk_rq_bytes(4096, 16) == 8192,
                "a request completed in parts: the last part is smaller than the request");
    assert_true(disk_rq_bytes(0, 0) == 0, "a flush has no data");
    assert_true(
        disk_rq_bytes(64 << 20, (u16)((64 << 20) >> 9)) == 64 << 20,
        "the sectors of a 64 MiB discard wrap on 16 bits: the completed bytes are the size");
}

static void test_fs_sync_status(void) {
    assert_true(fs_sync_status(0) == 0, "a successful sync has no status");
    assert_true(fs_sync_status(-5) == 5, "-EIO becomes errno 5");
    assert_true(fs_sync_status(-22) == 22, "-EINVAL becomes errno 22");
    assert_true(fs_sync_status(-512) == k_status_other,
                "-ERESTARTSYS doesn't fit in a status: it is not reported as a success");
    assert_true(fs_sync_status(-524) == k_status_other,
                "-ENOTSUPP doesn't fit in a status: it is not reported as ENOMEM");
    assert_true(!fs_sync_attempted(-9), "an invalid file descriptor is not a file sync");
    assert_true(fs_sync_attempted(-22), "a file that can't be synced is a failed file sync");
    assert_true(fs_sync_attempted(0), "a successful sync is a file sync");
}

static void test_sync_file_range_waits(void) {
    assert_true(!sync_file_range_waits(k_sync_file_range_write),
                "a SYNC_FILE_RANGE_WRITE hint doesn't wait for the writeback");
    assert_true(!sync_file_range_waits(0), "a call without flags doesn't wait");
    assert_true(sync_file_range_waits(k_sync_file_range_wait_before), "WAIT_BEFORE waits");
    assert_true(sync_file_range_waits(k_sync_file_range_wait_after), "WAIT_AFTER waits");
    assert_true(sync_file_range_waits(k_sync_file_range_wait_before | k_sync_file_range_write |
                                      k_sync_file_range_wait_after),
                "WAIT_BEFORE|WRITE|WAIT_AFTER waits");
    assert_true(!sync_file_range_waits(0xfffffff8u), "bits above the three flags are not waits");
}

int main(void) {
    test_latency_bucket_is_upper_inclusive();
    test_latency_bucket_without_bounds();
    test_latency_bucket_never_exceeds_the_bucket_array();
    test_final_completion();
    test_status_code();
    test_op_from_req_op();
    test_bio_op();
    test_queue_ns();
    test_rq_bytes();
    test_fs_sync_status();
    test_sync_file_range_waits();

    if (failed_assertions) {
        printf("%u assertion(s) failed\n", failed_assertions);
        return 1;
    }
    return 0;
}
