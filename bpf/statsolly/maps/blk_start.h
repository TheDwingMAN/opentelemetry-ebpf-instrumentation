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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 16);
    __type(key, struct blk_rq_key);
    __type(value, u64); // issue timestamp (ns)
    __uint(pinning, OBI_PIN_INTERNAL);
} blk_start SEC(".maps");
