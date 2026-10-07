// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
//go:build obi_bpf_ignore
#pragma once
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

// Issue timestamp of in-flight block requests, keyed by struct request pointer.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1 << 16);
    __type(key, u64);
    __type(value, u64);
    __uint(pinning, OBI_PIN_INTERNAL);
} block_rq_start SEC(".maps");
