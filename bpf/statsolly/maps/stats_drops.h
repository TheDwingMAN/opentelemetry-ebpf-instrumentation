// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

#include <statsolly/types.h>

// What the stats programs could not count because a map was full, per
// reason, per CPU. Userspace sums the CPUs, exports the totals as an internal
// metric and logs the first drop of each reason.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, k_stats_drop_max);
    __type(key, u32);
    __type(value, u64);
    __uint(pinning, OBI_PIN_INTERNAL);
} stats_drops SEC(".maps");

// A completion in interrupt context can interrupt a program that is counting
// a drop on the same CPU, so even the per-CPU counter is added to atomically.
static __always_inline void stats_count_drop(const enum stats_drop reason) {
    const u32 key = reason;
    u64 *const count = bpf_map_lookup_elem(&stats_drops, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
}
