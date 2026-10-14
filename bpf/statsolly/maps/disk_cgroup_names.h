// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

// Long enough for the container cgroup names of the common runtimes, like
// cri-containerd-<64 hex digits>.scope
enum { k_disk_cgroup_name_max_len = 128 };

typedef struct disk_cgroup_name {
    unsigned char name[k_disk_cgroup_name_max_len];
    // some runtimes run the processes of a container in a child cgroup of the container's
    unsigned char parent[k_disk_cgroup_name_max_len];
} disk_cgroup_name_t;

// The names of the cgroups that block I/O is charged to, and of their parents, by cgroup id, so
// that userspace finds the containers of cgroups outside its cgroup namespace or already gone. An
// LRU map can evict entries before it is full until the fix of Linux 6.16 (and 6.12.39, 6.6.99):
// the completion records the names again at the next I/O of the cgroup.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1 << 13);
    __type(key, u64);
    __type(value, disk_cgroup_name_t);
    __uint(pinning, OBI_PIN_INTERNAL);
} disk_cgroup_names SEC(".maps");
