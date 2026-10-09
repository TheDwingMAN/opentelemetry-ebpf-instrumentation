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
    assert_true(disk_rq_final_completion(4096, 4096), "completing all remaining bytes is final");
    assert_true(!disk_rq_final_completion(4096, 8192),
                "a partial completion is not final, even a failed one: the rest is retried or "
                "failed in another completion");
    assert_true(disk_rq_final_completion(0, 0), "a zero-byte request (flush) is final");
}

static void test_completed_before(void) {
    assert_true(disk_rq_completed_before(0, false, true),
                "device mapper ends a request after its bytes completed, with no bio left");
    assert_true(!disk_rq_completed_before(4096, true, true),
                "the completion of the bytes is counted");
    assert_true(
        !disk_rq_completed_before(0, false, false),
        "a request whose bios NVMe multipath took to retry them on another path is counted");
    assert_true(!disk_rq_completed_before(0, true, true),
                "an empty write keeps its bio: the empty flush of an fsync, or the end of a flush "
                "sequence, is counted");
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
    assert_true(disk_op_from_req_op(0, 0) == disk_op_read, "REQ_OP_READ is a read");
    assert_true(disk_op_from_req_op(1, 0) == disk_op_write, "REQ_OP_WRITE is a write");
    assert_true(disk_op_from_req_op(2, 0) == disk_op_unknown, "REQ_OP_FLUSH is not measured");
    assert_true(disk_op_from_req_op(3, 0) == disk_op_unknown, "REQ_OP_DISCARD is not measured");
    assert_true(disk_op_from_req_op(5, 0) == disk_op_unknown,
                "REQ_OP_SECURE_ERASE is not measured");
    assert_true(disk_op_from_req_op(9, 0) == disk_op_write, "REQ_OP_WRITE_ZEROES is a write");
    assert_true(disk_op_from_req_op(34, 0) == disk_op_unknown,
                "driver private operations are not measured");
    assert_true(disk_op_from_req_op(35, 0) == disk_op_unknown,
                "odd driver private operations are not measured");
}

// The REQ_OP_ZONE_APPEND values of the kernel BTFs, with the zoned operations that share or
// neighbour them
static void test_zone_append(void) {
    // Linux 5.8 and RHEL 8 (enum req_opf): ZONE_APPEND 13, WRITE_SAME 7
    assert_true(disk_op_from_req_op(13, 13) == disk_op_write, "a 5.8 zone append is a write");
    assert_true(disk_op_from_req_op(7, 13) == disk_op_unknown, "a 5.8 WRITE_SAME is not measured");

    // Linux 5.10 and 5.15 stable (enum req_opf): ZONE_APPEND 21, CLOSE 13, RESET 17
    assert_true(disk_op_from_req_op(21, 21) == disk_op_write, "a 5.10 zone append is a write");
    assert_true(disk_op_from_req_op(7, 21) == disk_op_unknown, "a 5.10 WRITE_SAME is not measured");
    assert_true(disk_op_from_req_op(13, 21) == disk_op_unknown, "a zone close is not measured");
    assert_true(disk_op_from_req_op(17, 21) == disk_op_unknown,
                "a 5.10 zone reset is not measured");

    // Linux 6.1+ and RHEL 9 (enum req_op): ZONE_APPEND 7, CLOSE 13 (RESET 13 on RHEL 9.6)
    assert_true(disk_op_from_req_op(7, 7) == disk_op_write, "a 6.1 zone append is a write");
    assert_true(disk_op_from_req_op(13, 7) == disk_op_unknown, "a zone reset is not an append");
    assert_true(disk_op_from_req_op(15, 7) == disk_op_unknown, "a zone finish is not measured");
    assert_true(disk_op_from_req_op(17, 7) == disk_op_unknown, "a 6.1 zone reset is not measured");

    // a kernel without REQ_OP_ZONE_APPEND
    assert_true(disk_op_from_req_op(7, 0) == disk_op_unknown,
                "op 7 is no zone append without the op");
    assert_true(disk_op_from_req_op(13, 0) == disk_op_unknown,
                "op 13 is no zone append without the op");
    assert_true(disk_op_from_req_op(21, 0) == disk_op_unknown,
                "op 21 is no zone append without the op");
    assert_true(disk_op_from_req_op(0, 0) == disk_op_read,
                "the missing op never turns reads into writes");
}

static void test_accounted_start_ns(void) {
    const u32 io_stat = 0x100;
    assert_true(disk_accounted_start_ns(1000, 0x20, 0) == 1000,
                "a kernel that writes the start at every allocation needs no flag");
    assert_true(disk_accounted_start_ns(0, 0, 0) == 0,
                "a start the kernel didn't record stays unknown without a flag");
    assert_true(disk_accounted_start_ns(1000, io_stat, io_stat) == 1000,
                "the start of an accounted request");
    assert_true(disk_accounted_start_ns(1000, io_stat | 0x2, io_stat) == 1000,
                "the start of an accounted request in a flush sequence");
    assert_true(disk_accounted_start_ns(1000, 0x20, io_stat) == 0,
                "the start of a request that is not accounted may be left by an earlier use");
    assert_true(disk_accounted_start_ns(1000, 0, io_stat) == 0,
                "a request without flags is not accounted");
    assert_true(disk_accounted_start_ns(0, io_stat, io_stat) == 0,
                "an accounted request without a start stays unknown");
}

int main(void) {
    test_latency_bucket_is_upper_inclusive();
    test_latency_bucket_without_bounds();
    test_latency_bucket_never_exceeds_the_bucket_array();
    test_final_completion();
    test_completed_before();
    test_status_code();
    test_op_from_req_op();
    test_zone_append();
    test_accounted_start_ns();

    if (failed_assertions) {
        printf("%u assertion(s) failed\n", failed_assertions);
        return 1;
    }
    return 0;
}
