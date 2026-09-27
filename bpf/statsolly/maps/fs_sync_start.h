// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

// Start time of the file sync in progress in each thread, keyed by pid_tgid
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1 << 12);
    __type(key, u64);
    __type(value, u64);
    __uint(pinning, OBI_PIN_INTERNAL);
} fs_sync_start SEC(".maps");
