// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

// Issue timestamp of each in-flight block request, keyed by the struct request address.
// LRU so that requests whose completion is never seen can't leak entries.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1 << 14);
    __type(key, u64);
    __type(value, u64);
    __uint(pinning, OBI_PIN_INTERNAL);
} disk_rq_start SEC(".maps");
