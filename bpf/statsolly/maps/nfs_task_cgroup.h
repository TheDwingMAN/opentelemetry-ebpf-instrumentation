// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

// The io controller cgroup of the thread that started each NFS RPC task, keyed by the address of
// the task. Asynchronous tasks complete in the rpciod workqueue, not in the thread that started
// them. Entries are overwritten when the kernel reuses the memory of a task for another one.
// Large enough for an LRU map not to evict tasks in progress on hosts with up to 128 CPUs, see
// disk_cgroup_names.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1 << 14);
    __type(key, u64);
    __type(value, u64);
    __uint(pinning, OBI_PIN_INTERNAL);
} nfs_task_cgroup SEC(".maps");
