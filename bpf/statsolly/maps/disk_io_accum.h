// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
//go:build obi_bpf_ignore
#pragma once
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>
#include <statsolly/types.h>

typedef struct disk_io_accum_key {
    u32 dev;
    enum disk_io_direction direction;
    u8 _pad[3];
} disk_io_accum_key_t;

typedef struct disk_io_accum {
    u64 first_ns;
    u32 latency_us[k_disk_io_batch_size];
    u8 count;
    u8 _pad[7];
} disk_io_accum_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1 << 10);
    __type(key, disk_io_accum_key_t);
    __type(value, disk_io_accum_t);
    __uint(pinning, OBI_PIN_INTERNAL);
} disk_io_accum SEC(".maps");
