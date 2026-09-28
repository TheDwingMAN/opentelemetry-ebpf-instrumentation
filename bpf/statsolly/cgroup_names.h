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

// The io controller cgroup of the current thread: the cgroup its direct block I/O is charged to
static __always_inline struct cgroup *current_io_cgroup(void) {
    if (!bpf_core_enum_value_exists(enum cgroup_subsys_id, io_cgrp_id)) {
        return 0;
    }
    const u32 io_id = bpf_core_enum_value(enum cgroup_subsys_id, io_cgrp_id);
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct css_set *cset = BPF_CORE_READ(task, cgroups);
    if (!cset) {
        return 0;
    }
    // the enum value is only known at load time, so the array element is read by address
    struct cgroup_subsys_state *const *subsys = __builtin_preserve_access_index(&cset->subsys[0]);
    struct cgroup_subsys_state *css = 0;
    bpf_probe_read_kernel(&css, sizeof(css), subsys + io_id);
    return BPF_CORE_READ(css, cgroup);
}

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
