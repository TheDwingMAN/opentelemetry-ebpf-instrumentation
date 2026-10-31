// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

#include <statsolly/maps/nfs_procedure_accum.h>

typedef struct nfs_procedure_cgroup_key {
    // the server, procedure, version and outcome of the RPC, as in nfs_procedure_accum
    nfs_procedure_key_t rpc;
    // the io controller cgroup of the thread that started the RPC, or 0 when it isn't known
    u64 cgroup_id;
} nfs_procedure_cgroup_key_t;

// Cumulative values: userspace reads them periodically and computes the deltas
typedef struct nfs_procedure_cgroup_accum {
    u64 count;
    u64 sum_ns;
} nfs_procedure_cgroup_accum_t;

// The RPCs and their execute time per workload, in a map apart from the histogram of the node, so
// that a full map never drops an RPC from the histogram. A plain hash map, as nfs_procedure_accum.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 13);
    __type(key, nfs_procedure_cgroup_key_t);
    __type(value, nfs_procedure_cgroup_accum_t);
    __uint(pinning, OBI_PIN_INTERNAL);
} nfs_procedure_cgroup_accum SEC(".maps");
