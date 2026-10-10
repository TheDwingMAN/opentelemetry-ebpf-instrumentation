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

// The io controller cgroup of the current thread: the cgroup that its direct block I/O is charged
// to, or null without the io controller
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

// The io controller cgroup that a bio is charged to, or null without CONFIG_BLK_CGROUP
static __always_inline struct cgroup *bio_cgroup(struct bio *bio) {
    if (!bio || !bpf_core_field_exists(bio->bi_blkg)) {
        return 0;
    }
    return BPF_CORE_READ(bio, bi_blkg, blkcg, css.cgroup);
}

// kernfs_node before Linux 5.5, whose id was a union (RHEL 8 kernels have the u64 in a kABI union)
union kernfs_node_id___old {
    u64 id;
} __attribute__((preserve_access_index));

struct kernfs_node___old {
    union kernfs_node_id___old id;
} __attribute__((preserve_access_index));

// The id of a cgroup, as bpf_get_current_cgroup_id() returns it, or 0 for a null cgroup
static __always_inline u64 cgroup_id_of(struct cgroup *cgrp) {
    if (!cgrp) {
        return 0;
    }
    struct kernfs_node *kn = BPF_CORE_READ(cgrp, kn);
    if (bpf_core_field_exists(kn->id)) {
        return BPF_CORE_READ(kn, id);
    }
    const struct kernfs_node___old *old = (const void *)kn;
    return BPF_CORE_READ(old, id.id);
}

// Records the name of the cgroup, and of its parent, the first time I/O, a sync or an NFS RPC is
// charged to it
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
    // the parent cgroup, through the css of the cgroup. The root cgroup has none.
    struct cgroup *parent = BPF_CORE_READ(cgrp, self.parent, cgroup);
    if (parent) {
        bpf_probe_read_kernel_str(
            name->parent, sizeof(name->parent), BPF_CORE_READ(parent, kn, name));
    }
    bpf_map_update_elem(&disk_cgroup_names, &cgroup_id, name, BPF_NOEXIST);
}
