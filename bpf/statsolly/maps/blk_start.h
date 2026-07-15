// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

struct blk_rq_key {
    u32 dev;
    u32 _pad;
    u64 sector;
};

// Self-evicting scratch map for in-flight request timing: entries that are
// never matched by a completion (merges, requeues, splits, error paths)
// would otherwise orphan and fill a plain HASH; LRU_HASH evicts the
// least-recently-used entry instead of failing writes once full.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1 << 16);
    __type(key, struct blk_rq_key);
    __type(value, u64); // issue timestamp (ns)
    __uint(pinning, OBI_PIN_INTERNAL);
} blk_start SEC(".maps");
