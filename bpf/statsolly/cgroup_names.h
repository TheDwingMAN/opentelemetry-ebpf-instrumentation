// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_builtins.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_core_read.h>

#include <common/scratch_mem.h>

#include <statsolly/maps/disk_cgroup_names.h>

SCRATCH_MEM_TYPED(disk_cgroup_name_init, disk_cgroup_name_t)

// Records the name of the cgroup the first time I/O is charged to it
static __always_inline void record_cgroup_name(const u64 cgroup_id, struct cgroup *cgrp) {
    if (bpf_map_lookup_elem(&disk_cgroup_names, &cgroup_id)) {
        return;
    }
    disk_cgroup_name_t *name = disk_cgroup_name_init_mem();
    if (!name) {
        return;
    }
    bpf_memset(name, 0, sizeof(*name));
    bpf_probe_read_kernel_str(name->name, sizeof(name->name), BPF_CORE_READ(cgrp, kn, name));
    bpf_map_update_elem(&disk_cgroup_names, &cgroup_id, name, BPF_NOEXIST);
}
