// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

#include <statsolly/maps/disk_rq_start.h>

// Each in-flight bio of the devices in disk_bio_devices, keyed by the struct bio address. LRU so
// that bios whose completion is never seen can't leak entries.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1 << 14);
    __type(key, u64);
    __type(value, disk_rq_start_t);
    __uint(pinning, OBI_PIN_INTERNAL);
} disk_bio_start SEC(".maps");
