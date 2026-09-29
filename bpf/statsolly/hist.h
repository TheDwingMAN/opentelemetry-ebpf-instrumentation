// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

// Exact histogram buckets for kernel-side aggregation, kept free of kernel
// types and map access so bpf/tests can check them natively.
//
// The bounds are load-time constants, in nanoseconds, sorted ascending and
// padded with U64_MAX after the last real bound. Userspace computes each
// bound as the largest nanosecond count whose time.Duration(n).Seconds() is
// <= the configured bound in seconds, so "v <= bound" here is exactly the
// float comparison the OTel SDK and the Prometheus client make on
// time.Duration(v).Seconds(): upper-inclusive buckets, the same as OTel
// explicit buckets and Prometheus "le".
//
// A value above every real bound lands in the overflow bucket, whose index is
// the number of real bounds: the first U64_MAX pad compares >= any value, and
// with no pad (every bound real) the search runs past the last bound.
enum {
    // Explicit layout: at most 32 bounds, 33 buckets.
    k_stat_hist_max_bounds = 32,
    // Exponential layout (a base-2 exponential boundary list at a fixed
    // scale): at most 128 bounds, 129 buckets.
    k_stat_hist_exp_max_bounds = 128,
};

// stat_hist_idx returns the index of the first bound >= v in a 32-entry bound
// array, or 32 when there is none. An unrolled binary search: after the step
// of size s the answer lies in [i, i + s], so five halvings and one final
// comparison resolve all 33 outcomes. The masks only prove the index range to
// the verifier; i + s - 1 never exceeds 31.
static __always_inline u32 stat_hist_idx(const volatile u64 *bounds, const u64 v) {
    u32 i = 0;
    if (v > bounds[15]) {
        i = 16;
    }
    if (v > bounds[(i + 7) & 31]) {
        i += 8;
    }
    if (v > bounds[(i + 3) & 31]) {
        i += 4;
    }
    if (v > bounds[(i + 1) & 31]) {
        i += 2;
    }
    if (v > bounds[i & 31]) {
        i += 1;
    }
    if (v > bounds[i & 31]) {
        i += 1;
    }
    return i;
}

// stat_hist_exp_idx is stat_hist_idx for the 128-entry exponential layout:
// seven halvings and one final comparison resolve all 129 outcomes.
static __always_inline u32 stat_hist_exp_idx(const volatile u64 *bounds, const u64 v) {
    u32 i = 0;
    if (v > bounds[63]) {
        i = 64;
    }
    if (v > bounds[(i + 31) & 127]) {
        i += 32;
    }
    if (v > bounds[(i + 15) & 127]) {
        i += 16;
    }
    if (v > bounds[(i + 7) & 127]) {
        i += 8;
    }
    if (v > bounds[(i + 3) & 127]) {
        i += 4;
    }
    if (v > bounds[(i + 1) & 127]) {
        i += 2;
    }
    if (v > bounds[i & 127]) {
        i += 1;
    }
    if (v > bounds[i & 127]) {
        i += 1;
    }
    return i;
}

// stat_hist_add counts one value in bucket idx of a 33-bucket explicit
// layout. Different programs (issue and complete, fs entry and exit) share
// per-CPU values and can interleave on one CPU, so even per-CPU buckets are
// updated atomically.
static __always_inline void stat_hist_add(u32 *buckets, const u32 idx) {
    if (idx > k_stat_hist_max_bounds) {
        return;
    }
    __sync_fetch_and_add(&buckets[idx], 1);
}

// stat_hist_exp_add is stat_hist_add for the 129-bucket exponential layout.
static __always_inline void stat_hist_exp_add(u32 *buckets, const u32 idx) {
    if (idx > k_stat_hist_exp_max_bounds) {
        return;
    }
    __sync_fetch_and_add(&buckets[idx], 1);
}
