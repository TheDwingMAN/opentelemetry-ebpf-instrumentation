// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

struct blk_dev_state {
    u64 inflight; // current queue depth
};

// Tracks per-device queue depth across issue/complete so each completion
// event can carry the current inflight count; the ring buffer event is the
// only consumer, there is no userspace map polling. Keyed by kernel dev_t.
// Plain HASH, not LRU: losing a device's counter mid-flight would corrupt
// the inflight count (double-decrement or underflow on the next completion),
// so entries must never be evicted under map pressure.
// Issue increments only the first time a request is seen (a re-issue of an
// already in-flight request does not); complete decrements on every
// completion, matched or not, clamped at zero. This keeps the counter from
// drifting up when a completion's blk_start entry is missing.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 10);
    __type(key, u32);
    __type(value, struct blk_dev_state);
    __uint(pinning, OBI_PIN_INTERNAL);
} blk_dev_state SEC(".maps");
