// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Run from repo root:
//   make -C bpf/tests test_stat_hist && bpf/tests/test_stat_hist
// Run from bpf/tests:
//   make test_stat_hist && ./test_stat_hist

#include <stdbool.h>
#include <stdio.h>

#include <statsolly/hist.h>

static unsigned int failed_assertions;
static unsigned int passed_assertions;

// check prints only failures: the exhaustive cases below run thousands of
// assertions.
static void check(bool condition, const char *message, const u32 nbounds, const u64 v) {
    if (condition) {
        passed_assertions++;
        return;
    }
    failed_assertions++;
    printf("FAIL: %s (nbounds %u, v %llu)\n", message, nbounds, (unsigned long long)v);
}

static void assert_true(bool condition, const char *message) {
    if (condition) {
        passed_assertions++;
        printf("PASS: %s\n", message);
        return;
    }
    failed_assertions++;
    printf("FAIL: %s\n", message);
}

static const u64 k_u64_max = ~(u64)0;

// The reference: the first bound >= v, or the number of real bounds when v is
// above all of them.
static u32 linear_idx(const volatile u64 *bounds, const u32 nbounds, const u64 v) {
    for (u32 i = 0; i < nbounds; i++) {
        if (v <= bounds[i]) {
            return i;
        }
    }
    return nbounds;
}

static volatile u64 explicit_bounds[k_stat_hist_max_bounds];
static volatile u64 exp_bounds[k_stat_hist_exp_max_bounds];

// Fills the first nbounds entries with strictly increasing bounds starting at
// first, spaced by a growing step, and pads the rest with U64_MAX as the
// loader does.
static void fill(volatile u64 *bounds, const u32 size, const u32 nbounds, const u64 first) {
    u64 b = first;
    for (u32 i = 0; i < size; i++) {
        if (i < nbounds) {
            bounds[i] = b;
            b += 3 + (u64)i * 1000;
        } else {
            bounds[i] = k_u64_max;
        }
    }
}

// Every bound, one below and one above it, 0 and U64_MAX, against the linear
// reference.
static void check_explicit(const u32 nbounds, const u64 first) {
    fill(explicit_bounds, k_stat_hist_max_bounds, nbounds, first);
    const u64 probes[] = {0, 1, k_u64_max, k_u64_max - 1};
    for (u32 p = 0; p < sizeof(probes) / sizeof(probes[0]); p++) {
        const u64 v = probes[p];
        check(stat_hist_idx(explicit_bounds, v) == linear_idx(explicit_bounds, nbounds, v),
              "explicit edge value",
              nbounds,
              v);
    }
    for (u32 i = 0; i < nbounds; i++) {
        const u64 b = explicit_bounds[i];
        check(stat_hist_idx(explicit_bounds, b) == i,
              "a value equal to a bound is in its bucket",
              nbounds,
              b);
        if (b > 0) {
            check(stat_hist_idx(explicit_bounds, b - 1) ==
                      linear_idx(explicit_bounds, nbounds, b - 1),
                  "one below a bound",
                  nbounds,
                  b - 1);
        }
        check(stat_hist_idx(explicit_bounds, b + 1) == linear_idx(explicit_bounds, nbounds, b + 1),
              "one above a bound",
              nbounds,
              b + 1);
    }
}

static void check_exp(const u32 nbounds, const u64 first) {
    fill(exp_bounds, k_stat_hist_exp_max_bounds, nbounds, first);
    const u64 probes[] = {0, 1, k_u64_max, k_u64_max - 1};
    for (u32 p = 0; p < sizeof(probes) / sizeof(probes[0]); p++) {
        const u64 v = probes[p];
        check(stat_hist_exp_idx(exp_bounds, v) == linear_idx(exp_bounds, nbounds, v),
              "exponential edge value",
              nbounds,
              v);
    }
    for (u32 i = 0; i < nbounds; i++) {
        const u64 b = exp_bounds[i];
        check(stat_hist_exp_idx(exp_bounds, b) == i,
              "a value equal to a bound is in its bucket",
              nbounds,
              b);
        if (b > 0) {
            check(stat_hist_exp_idx(exp_bounds, b - 1) == linear_idx(exp_bounds, nbounds, b - 1),
                  "one below a bound",
                  nbounds,
                  b - 1);
        }
        check(stat_hist_exp_idx(exp_bounds, b + 1) == linear_idx(exp_bounds, nbounds, b + 1),
              "one above a bound",
              nbounds,
              b + 1);
    }
}

static void test_explicit_every_bound_count(void) {
    // Every number of real bounds, with 0 as the first bound (the OTel default
    // duration buckets start at 0) and without.
    for (u32 n = 0; n <= k_stat_hist_max_bounds; n++) {
        check_explicit(n, 0);
        check_explicit(n, 100000);
    }
    assert_true(failed_assertions == 0, "explicit search matches a linear search for 0..32 bounds");
}

static void test_exp_every_bound_count(void) {
    for (u32 n = 0; n <= k_stat_hist_exp_max_bounds; n++) {
        check_exp(n, 0);
        check_exp(n, 953);
    }
    assert_true(failed_assertions == 0,
                "exponential search matches a linear search for 0..128 bounds");
}

static void test_explicit_named_cases(void) {
    fill(explicit_bounds, k_stat_hist_max_bounds, 0, 0);
    assert_true(stat_hist_idx(explicit_bounds, 12345) == 0,
                "no bounds: every value is in the overflow bucket 0");
    assert_true(stat_hist_idx(explicit_bounds, k_u64_max) == 0,
                "no bounds: U64_MAX is in bucket 0");

    fill(explicit_bounds, k_stat_hist_max_bounds, 1, 1000);
    assert_true(stat_hist_idx(explicit_bounds, 0) == 0, "one bound: 0 is in bucket 0");
    assert_true(stat_hist_idx(explicit_bounds, 1000) == 0, "one bound: the bound is in bucket 0");
    assert_true(stat_hist_idx(explicit_bounds, 1001) == 1, "one bound: above it is overflow 1");
    assert_true(stat_hist_idx(explicit_bounds, k_u64_max) == 1, "one bound: U64_MAX is overflow 1");

    fill(explicit_bounds, k_stat_hist_max_bounds, k_stat_hist_max_bounds, 10);
    const u64 last = explicit_bounds[k_stat_hist_max_bounds - 1];
    assert_true(stat_hist_idx(explicit_bounds, last) == 31,
                "32 bounds: the last bound is bucket 31");
    assert_true(stat_hist_idx(explicit_bounds, last + 1) == 32,
                "32 bounds: above the last bound is overflow 32");
    assert_true(stat_hist_idx(explicit_bounds, k_u64_max) == 32,
                "32 bounds: U64_MAX is overflow 32");
}

static void test_exp_named_cases(void) {
    fill(exp_bounds, k_stat_hist_exp_max_bounds, k_stat_hist_exp_max_bounds, 0);
    const u64 last = exp_bounds[k_stat_hist_exp_max_bounds - 1];
    assert_true(stat_hist_exp_idx(exp_bounds, 0) == 0, "128 bounds: 0 is the zero bucket");
    assert_true(stat_hist_exp_idx(exp_bounds, last) == 127, "128 bounds: the last bound is 127");
    assert_true(stat_hist_exp_idx(exp_bounds, last + 1) == 128, "128 bounds: overflow is 128");
    assert_true(stat_hist_exp_idx(exp_bounds, k_u64_max) == 128, "128 bounds: U64_MAX is 128");
}

static void test_add(void) {
    u32 buckets[k_stat_hist_max_bounds + 1] = {};
    stat_hist_add(buckets, 0);
    stat_hist_add(buckets, 32);
    stat_hist_add(buckets, 32);
    stat_hist_add(buckets, 33);
    assert_true(buckets[0] == 1 && buckets[32] == 2, "stat_hist_add counts in the bucket");

    u32 sum = 0;
    for (u32 i = 0; i <= k_stat_hist_max_bounds; i++) {
        sum += buckets[i];
    }
    assert_true(sum == 3, "stat_hist_add ignores an index past the overflow bucket");

    u32 exp_buckets[k_stat_hist_exp_max_bounds + 1] = {};
    stat_hist_exp_add(exp_buckets, 128);
    stat_hist_exp_add(exp_buckets, 129);
    assert_true(exp_buckets[128] == 1, "stat_hist_exp_add counts the overflow bucket once");
}

int main(void) {
    test_explicit_every_bound_count();
    test_exp_every_bound_count();
    test_explicit_named_cases();
    test_exp_named_cases();
    test_add();

    if (failed_assertions > 0) {
        printf("%u assertion(s) failed, %u passed\n", failed_assertions, passed_assertions);
        return 1;
    }
    printf("all %u assertions passed\n", passed_assertions);
    return 0;
}
