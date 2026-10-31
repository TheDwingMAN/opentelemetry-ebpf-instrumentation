// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

typedef struct nfs_task_cgroup {
    // the io controller cgroup of the thread that started the task, or 0 without one
    u64 cgroup_id;
    // the tk_owner of the task, the process of that thread
    u32 owner;
    u8 _pad[4];
} nfs_task_cgroup_t;

// The cgroup of the thread that started each NFS RPC task, keyed by the address of the task: the
// asynchronous tasks complete in an rpciod worker. No tracepoint marks the release of a task, so
// the entries are never deleted: the start of a task writes over the entry of its address, and an
// LRU map, sized like the in-flight maps, evicts the least recently used, tasks in flight included.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1 << 14);
    __type(key, u64);
    __type(value, nfs_task_cgroup_t);
    __uint(pinning, OBI_PIN_INTERNAL);
} nfs_task_cgroup SEC(".maps");
