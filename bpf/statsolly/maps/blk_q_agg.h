// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

#include <statsolly/blk_helpers.h>
#include <statsolly/hist.h>

// Queue wait of the completed reads and writes that have one, keyed as
// blk_agg (maps/blk_agg.h). A map of its own: the queue wait is optional, and
// in blk_agg it would add a sum and a bucket array to every value.

struct blk_queue_agg_val {
    u64 queue_sum_ns;
    u32 queue_bkt[k_stat_hist_max_bounds + 1];
    u32 _pad;
};

struct blk_queue_agg_exp_val {
    u64 queue_sum_ns;
    u32 queue_bkt[k_stat_hist_exp_max_bounds + 1];
    u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 1);
    __type(key, struct blk_agg_key);
    __type(value, struct blk_queue_agg_val);
    __uint(pinning, OBI_PIN_INTERNAL);
} blk_q_agg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 1);
    __type(key, struct blk_agg_key);
    __type(value, struct blk_queue_agg_exp_val);
    __uint(pinning, OBI_PIN_INTERNAL);
} blk_q_agg_exp SEC(".maps");
