// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

#include <statsolly/blk_helpers.h>
#include <statsolly/hist.h>

// Completed block requests counted in the kernel, per device, kind and errno
// (AGG emit mode). Each CPU counts in its own copy of a value, which
// userspace sums. The explicit map holds the union of the exporters' bucket
// bounds, the exponential one a base-2 exponential boundary list; only the
// one in use has more than one entry. Plain PERCPU_HASH, preallocated: a
// full map never evicts a live key, it fails the insert and counts a drop.
// Userspace sizes them from the devices and a memory budget, and deletes
// idle keys.

// Service time and bytes of every completed request.
struct blk_agg_val {
    u64 bytes;
    u64 svc_sum_ns;
    u32 svc_bkt[k_stat_hist_max_bounds + 1];
    u32 _pad;
};

struct blk_agg_exp_val {
    u64 bytes;
    u64 svc_sum_ns;
    u32 svc_bkt[k_stat_hist_exp_max_bounds + 1];
    u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 1);
    __type(key, struct blk_agg_key);
    __type(value, struct blk_agg_val);
    __uint(pinning, OBI_PIN_INTERNAL);
} blk_agg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 1);
    __type(key, struct blk_agg_key);
    __type(value, struct blk_agg_exp_val);
    __uint(pinning, OBI_PIN_INTERNAL);
} blk_agg_exp SEC(".maps");
