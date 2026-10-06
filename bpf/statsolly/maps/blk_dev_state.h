// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

struct blk_dev_state {
    u64 inflight; // current queue depth
};

// Per-device count of requests in flight, carried by each completion event
// for the deprecated obi.stat.disk.queue.depth metric. Only maintained when
// that metric is enabled (blk_want_queue_depth); userspace sizes the map to
// one entry otherwise. Keyed by kernel dev_t. Plain HASH, not LRU: losing a
// device's counter mid-flight would corrupt its count. The count goes up only
// when a request gets an in-flight entry and down only when that entry is
// deleted, so every decrement pairs with an increment.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 10);
    __type(key, u32);
    __type(value, struct blk_dev_state);
    __uint(pinning, OBI_PIN_INTERNAL);
} blk_dev_state SEC(".maps");
