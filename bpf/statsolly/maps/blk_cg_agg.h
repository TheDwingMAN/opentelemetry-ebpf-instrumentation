// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

#include <statsolly/blk_helpers.h>

// Completed block reads and writes per cgroup they were charged to, device
// and direction (storage_block_pod): the counts behind
// obi.stat.disk.operations, obi.stat.disk.operation_time and the
// pod-attributed obi.stat.disk.io. I/O charged to no cgroup has id 0 and
// is counted too, so that the keys of a device and direction add up to its
// node-level series.
//
// Per CPU: a pod doing I/O on many CPUs at once would otherwise move one
// value's cache line between them on every completion, which the scaling
// benchmark (blk_cg_scaling_privileged_test.go) measured at 19 ns per update
// on 1 CPU and about 900 ns on 10 for a shared HASH, against 19-25 ns for
// this map. Userspace sizes it from the pods, devices and a memory budget,
// and deletes idle keys once their cgroup's tombstone has expired.
struct blk_cg_val {
    u64 count;
    u64 bytes;
    u64 time_ns; // blk_op_time_ns
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 1);
    __type(key, struct blk_cg_key);
    __type(value, struct blk_cg_val);
    __uint(pinning, OBI_PIN_INTERNAL);
} blk_cg_agg SEC(".maps");
