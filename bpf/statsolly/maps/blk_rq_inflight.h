// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

#include <statsolly/blk_helpers.h>

// Requests between issue and final completion, keyed by the struct request
// pointer the raw tracepoints hand over. The pointer tells apart requests that
// share a device and sector (the flush requests of several hardware queues);
// the kernel reuses request structs, so an entry left behind by a missed
// completion is overwritten when its struct is next issued rather than leaking
// for good. Plain HASH, not LRU: evicting an in-flight entry would lose its
// completion. Userspace sizes it from sysfs, or to one entry when the classic
// tracepoints are in use.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 16);
    __type(key, u64); // struct request pointer
    __type(value, struct blk_rq_inflight);
    __uint(pinning, OBI_PIN_INTERNAL);
} blk_rq_inflight SEC(".maps");

struct blk_rq_key {
    u32 dev;
    u32 _pad;
    u64 sector;
};

// The classic tracepoints have no request pointer, only the device and start
// sector, so they keep that key. Such keys are not reused the way request
// structs are, so a missed completion would orphan its entry; LRU_HASH evicts
// the least-recently-used entry instead of failing writes once full.
// Userspace sizes it to one entry when the raw tracepoints are in use.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1 << 16);
    __type(key, struct blk_rq_key);
    __type(value, struct blk_rq_inflight);
    __uint(pinning, OBI_PIN_INTERNAL);
} blk_rq_inflight_sector SEC(".maps");
