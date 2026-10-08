// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

// The request queues whose requests the kernel times (rq->io_start_time_ns), keyed by the struct
// request_queue address. Their requests are not recorded in disk_rq_start at their issue: their
// completion reads what the kernel recorded instead. A queue is added when a completion finds the
// kernel's timestamp, and removed when a measured request (read, write, flush or discard) of the
// queue completes with neither. LRU so that removed queues are forgotten. Userspace grows it to at
// least 256 entries per CPU (sizeInFlightMaps): before Linux 6.16, except from 6.12.39, 6.6.99,
// RHEL 9.8 and RHEL 10.2, which have the fix, a small LRU map evicts live queues once the CPUs keep
// most of it as free entries for themselves, and the next requests of an evicted queue are recorded
// at their issue but complete with the kernel's timestamp, which leaves their records in
// disk_rq_start.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1 << 10);
    __type(key, u64);
    __type(value, u8);
    __uint(pinning, OBI_PIN_INTERNAL);
} disk_timed_queues SEC(".maps");
