// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

// Long enough for the container cgroup names of the common runtimes, e.g.
// cri-containerd-<64 hex digits>.scope
enum { k_disk_cgroup_name_max_len = 128 };

typedef struct disk_cgroup_name {
    unsigned char name[k_disk_cgroup_name_max_len];
    // the name of the parent cgroup: some runtimes run the processes of a container in a child
    // cgroup of the container's, e.g. crun in a `container` cgroup on cgroup v2
    unsigned char parent[k_disk_cgroup_name_max_len];
} disk_cgroup_name_t;

// Name of the cgroups that block I/O or file syncs are charged to, and of their parent, keyed by
// cgroup id. The kernel records them when it starts accumulating I/O or syncs for a cgroup, so that
// userspace can tell the container from the names even when the cgroup is not visible from its
// cgroup namespace, or already gone. An LRU map evicts entries once more than max_entries / 128
// CPUs have added some (before Linux 6.16, except from 6.12.39, 6.6.99, RHEL 9.8 and RHEL 10.2,
// which have the fix): the kernel records the names again at the next I/O or sync of the cgroup.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1 << 13);
    __type(key, u64);
    __type(value, disk_cgroup_name_t);
    __uint(pinning, OBI_PIN_INTERNAL);
} disk_cgroup_names SEC(".maps");
