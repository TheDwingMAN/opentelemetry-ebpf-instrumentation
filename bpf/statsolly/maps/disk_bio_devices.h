// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

// The bio-based stacked devices (device mapper, md RAID) whose bios are measured, keyed by their
// kernel dev_t. Userspace keeps it up to date, so that bios of other devices are skipped at once.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 8);
    __type(key, u32);
    __type(value, u8);
    __uint(pinning, OBI_PIN_INTERNAL);
} disk_bio_devices SEC(".maps");
