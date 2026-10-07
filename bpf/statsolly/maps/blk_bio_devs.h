// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

// The stacked volumes whose bios are measured: the bio-based device-mapper
// and md devices that nothing is stacked on (an LVM logical volume, an md
// array, a dm-crypt device), keyed by the dev_t of the whole disk
// (MKDEV(gendisk major, first_minor)). Userspace fills it from sysfs and
// keeps it in line as volumes come and go. Their I/O never reaches the block
// request tracepoints under their own name: the driver clones each bio onto
// the devices below, and only those issue requests.
//
// Leaf volumes only: every lower dm or md layer sees a clone of each bio, so
// tracking a thin pool and its data device next to the thin volume would
// measure one I/O three times. Bio-based only: see maps/blk_bio_inflight.h.
// Plain HASH, not LRU: a volume must never be silently evicted.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 10);
    __type(key, u32);
    __type(value, u8);
    __uint(pinning, OBI_PIN_INTERNAL);
} blk_bio_devs SEC(".maps");
