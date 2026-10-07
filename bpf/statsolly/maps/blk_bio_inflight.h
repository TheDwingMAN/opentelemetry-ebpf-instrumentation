// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

#include <statsolly/blk_helpers.h>

// Bios of tracked volumes between block_bio_queue and block_bio_complete,
// keyed by the struct bio pointer both tracepoints hand over. The value is
// that of blk_rq_inflight, so pending_operations counts the entries of both
// maps the same way. Plain HASH, not LRU: evicting an in-flight entry would
// lose its completion, and an LRU evicts long before it is full on hosts with
// many CPUs.
//
// Only bios of bio-based devices may enter: block_bio_complete never fires
// for a bio that reaches a request-based device as it is, without being
// cloned (blk_update_request ends it with its completion already traced by
// block_rq_complete), so its entry would stay until the pointer is reused.
// The set of tracked volumes (maps/blk_bio_devs.h) holds bio-based devices
// only, and the bio programs look a bio's disk up there before inserting.
// An entry whose completion was missed is overwritten when the kernel reuses
// its struct bio, and userspace deletes the ones left for minutes.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 16);
    __type(key, u64); // struct bio pointer
    __type(value, struct blk_rq_inflight);
    __uint(pinning, OBI_PIN_INTERNAL);
} blk_bio_inflight SEC(".maps");
