// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Run from repo root:
//   make -C bpf/tests test_nfs_rpc && bpf/tests/test_nfs_rpc
// Run from bpf/tests:
//   make test_nfs_rpc && ./test_nfs_rpc

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include <statsolly/nfs_rpc.h>

static unsigned int failed_assertions;

static void assert_true(bool condition, const char *message) {
    if (condition) {
        printf("PASS: %s\n", message);
        return;
    }

    failed_assertions++;
    printf("FAIL: %s\n", message);
}

// tk_status values S0-c observed at rpc_stats_latency.
static void test_status(void) {
    assert_true(nfs_rpc_status(65536, true) == 0,
                "a successful READ or WRITE leaves its byte count: no error");
    assert_true(nfs_rpc_status(0, true) == 0, "a READ at end of file leaves 0: no error");
    assert_true(nfs_rpc_status(-13, true) == -13, "EACCES is kept");
    assert_true(nfs_rpc_status(-2, true) == -2, "ENOENT on LOOKUP is kept");
    assert_true(nfs_rpc_status(-528, true) == -528, "a v3 JUKEBOX (EJUKEBOX) is kept");
    assert_true(nfs_rpc_status(-10008, true) == -10008, "a raw v4 NFS4ERR_DELAY is kept");
    assert_true(nfs_rpc_status(-13, false) == 0,
                "without the errors metric, errors do not split the keys");
}

static void test_retrans(void) {
    assert_true(nfs_rpc_retrans(1) == 0, "a request sent once was not retransmitted");
    assert_true(nfs_rpc_retrans(0) == 0, "a request never sent was not retransmitted");
    assert_true(nfs_rpc_retrans(3) == 2, "a request sent three times was retransmitted twice");
    assert_true(nfs_rpc_retrans(-1) == 0, "a negative count is no retransmission");
}

static void test_execute(void) {
    assert_true(nfs_rpc_execute(10401886000) == 10401886000ULL,
                "an attempt after a JUKEBOX keeps its 10 s execute time");
    assert_true(nfs_rpc_execute(0) == 0, "0 ns is 0 ns");
    assert_true(nfs_rpc_execute(-5) == 0, "a negative execute time counts as 0 ns");
}

// The key is hashed as raw bytes: it must have no compiler padding, and
// userspace reads it at fixed offsets (pkg/internal/statsolly/ebpf/nfs_key.go).
static void test_key_layout(void) {
    assert_true(sizeof(struct nfs_rpc_key) == 40, "struct nfs_rpc_key is 40 bytes");
    assert_true(offsetof(struct nfs_rpc_key, owner) == 0,
                "owner (step 19) is the key's first member");
    assert_true(offsetof(struct nfs_rpc_key, statidx) == 8 &&
                    offsetof(struct nfs_rpc_key, vers) == 10 &&
                    offsetof(struct nfs_rpc_key, family) == 11 &&
                    offsetof(struct nfs_rpc_key, status) == 12 &&
                    offsetof(struct nfs_rpc_key, addr) == 16 &&
                    offsetof(struct nfs_rpc_key, scope_id) == 32,
                "struct nfs_rpc_key members are where userspace reads them");
    assert_true(sizeof(struct nfs_rpc_val) == 168, "struct nfs_rpc_val is 168 bytes");
    assert_true(offsetof(struct nfs_rpc_val, bkt) == 32, "the buckets follow the four counters");
}

int main(void) {
    test_status();
    test_retrans();
    test_execute();
    test_key_layout();

    if (failed_assertions > 0) {
        printf("%u assertion(s) failed\n", failed_assertions);
        return 1;
    }
    printf("All tests passed\n");
    return 0;
}
