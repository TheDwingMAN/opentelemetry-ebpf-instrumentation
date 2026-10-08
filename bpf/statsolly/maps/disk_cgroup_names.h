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
} disk_cgroup_name_t;

// Name of the cgroups that block I/O is charged to, keyed by cgroup id. The kernel records it
// when it starts accumulating I/O for a cgroup, so that userspace can tell the container from
// the name even when the cgroup is not visible from its cgroup namespace, or already gone. An LRU
// map evicts entries once more than max_entries / 128 CPUs have added some (before Linux 6.16, and
// 6.12.39, 6.6.99, RHEL 9.8): the kernel records the name again at the next I/O of the cgroup.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1 << 13);
    __type(key, u64);
    __type(value, disk_cgroup_name_t);
    __uint(pinning, OBI_PIN_INTERNAL);
} disk_cgroup_names SEC(".maps");
