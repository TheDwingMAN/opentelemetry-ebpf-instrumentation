// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_builtins.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_core_read.h>
#include <bpfcore/bpf_tracing.h>

#include <common/scratch_mem.h>

#include <statsolly/cgroup_names.h>
#include <statsolly/disk_io.h>
#include <statsolly/types.h>
#include <statsolly/maps/fs_sync_accum.h>
#include <statsolly/maps/fs_sync_start.h>

// To be injected from userspace during eBPF program load & initialization.
volatile const u64 fs_sync_latency_bounds_ns[k_disk_latency_max_bounds];
volatile const u32 fs_sync_latency_bounds_len;

SCRATCH_MEM_TYPED(fs_sync_accum_init, fs_sync_accum_t)

// Force structs into the ELF for automatic creation of Golang struct
const fs_sync_key_t *unused_fs_sync_key __attribute__((unused));
const fs_sync_accum_t *unused_fs_sync_accum __attribute__((unused));

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

static __always_inline fs_sync_accum_t *lookup_or_init_fs_sync_accum(const fs_sync_key_t *key) {
    fs_sync_accum_t *accum = bpf_map_lookup_elem(&fs_sync_accum, key);
    if (accum) {
        return accum;
    }
    fs_sync_accum_t *init = fs_sync_accum_init_mem();
    if (!init) {
        return 0;
    }
    bpf_memset(init, 0, sizeof(*init));
    // BPF_NOEXIST: another CPU may have created the entry since the lookup above
    bpf_map_update_elem(&fs_sync_accum, key, init, BPF_NOEXIST);
    return bpf_map_lookup_elem(&fs_sync_accum, key);
}

// Starts measuring the file sync of the current thread. File syncs nest when a caller of
// vfs_fsync_range is probed too, and when a stacked filesystem, like overlayfs, syncs the file
// below: the innermost call is measured, once, and a thread whose kretprobe was missed recovers on
// its next sync.
static __always_inline void fs_sync_started(void) {
    const u64 pid_tgid = bpf_get_current_pid_tgid();
    const u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&fs_sync_start, &pid_tgid, &now, BPF_ANY);
}

static __always_inline void fs_sync_returned(const s32 ret) {
    const u64 pid_tgid = bpf_get_current_pid_tgid();
    const u64 *started_ns = bpf_map_lookup_elem(&fs_sync_start, &pid_tgid);
    if (!started_ns) {
        return;
    }
    const u64 latency_ns = bpf_ktime_get_ns() - *started_ns;
    bpf_map_delete_elem(&fs_sync_start, &pid_tgid);
    if (!fs_sync_attempted(ret)) {
        return;
    }

    struct cgroup *cgrp = current_io_cgroup();
    const fs_sync_key_t key = {
        .cgroup_id = BPF_CORE_READ(cgrp, kn, id),
        .status = fs_sync_status(ret),
    };
    fs_sync_accum_t *accum = lookup_or_init_fs_sync_accum(&key);
    if (!accum) {
        return;
    }
    if (cgrp) {
        record_cgroup_name(key.cgroup_id, cgrp);
    }
    const u32 bucket =
        disk_latency_bucket(fs_sync_latency_bounds_ns, fs_sync_latency_bounds_len, latency_ns);
    if (bucket >= k_disk_latency_max_buckets) {
        return;
    }
    __sync_fetch_and_add(&accum->latency_count[bucket], 1);
    __sync_fetch_and_add(&accum->latency_sum_ns[bucket], latency_ns);
}

// vfs_fsync_range serves fsync(2), fdatasync(2), O_SYNC and O_DSYNC writes, msync(2) with
// MS_SYNC, and their io_uring equivalents.
SEC("kprobe/vfs_fsync_range")
int BPF_KPROBE(obi_stats_kprobe_vfs_fsync_range) {
    (void)ctx;
    fs_sync_started();
    return 0;
}

SEC("kretprobe/vfs_fsync_range")
int BPF_KRETPROBE(obi_stats_kretprobe_vfs_fsync_range, int ret) {
    (void)ctx;
    fs_sync_returned(ret);
    return 0;
}

// do_fsync serves fsync(2) and fdatasync(2). Some kernel builds inline vfs_fsync_range into it, so
// that the vfs_fsync_range probes miss them. It is a function of its own since Linux 6.12 only:
// userspace attaches these probes when the kernel has it.
SEC("kprobe/do_fsync")
int BPF_KPROBE(obi_stats_kprobe_do_fsync) {
    (void)ctx;
    fs_sync_started();
    return 0;
}

SEC("kretprobe/do_fsync")
int BPF_KRETPROBE(obi_stats_kretprobe_do_fsync, int ret) {
    (void)ctx;
    fs_sync_returned(ret);
    return 0;
}
