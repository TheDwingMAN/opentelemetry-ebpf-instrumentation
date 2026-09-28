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

// The file that a file descriptor of the current thread refers to, or null
static __always_inline struct file *current_file(const u32 fd) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct fdtable *fdt = BPF_CORE_READ(task, files, fdt);
    if (!fdt || fd >= BPF_CORE_READ(fdt, max_fds)) {
        return 0;
    }
    struct file **fds = BPF_CORE_READ(fdt, fd);
    struct file *file = 0;
    bpf_probe_read_kernel(&file, sizeof(file), fds + fd);
    return file;
}

static __always_inline u32 file_s_dev(struct file *file) {
    return BPF_CORE_READ(file, f_inode, i_sb, s_dev);
}

// The first argument of a system call, which syscall wrappers get in the pt_regs of the caller
static __always_inline u32 syscall_fd(struct pt_regs *ctx) {
    struct pt_regs *regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
    u32 fd = 0;
    bpf_probe_read_kernel(&fd, sizeof(fd), (void *)&PT_REGS_PARM1(regs));
    return fd;
}

// Starts measuring a sync system call of the current thread, which the kernel functions it
// calls leave alone
static __always_inline void syscall_sync_started(const enum fs_sync_type type, const u32 s_dev) {
    const u64 pid_tgid = bpf_get_current_pid_tgid();
    const fs_sync_start_t start = {
        .started_ns = bpf_ktime_get_ns(),
        .s_dev = s_dev,
        .type = type,
        .from_syscall = 1,
    };
    bpf_map_update_elem(&fs_sync_start, &pid_tgid, &start, BPF_ANY);
}

// Starts measuring a file sync that a kernel function does outside of the sync system calls:
// O_SYNC and O_DSYNC writes, msync(2), io_uring, the NFS server... File syncs nest when a
// stacked filesystem, like overlayfs, syncs the file below: the innermost call is measured,
// once, and a thread whose kretprobe was missed recovers on its next sync.
static __always_inline void function_sync_started(const int datasync, struct file *file) {
    const u64 pid_tgid = bpf_get_current_pid_tgid();
    const fs_sync_start_t *current = bpf_map_lookup_elem(&fs_sync_start, &pid_tgid);
    if (current && current->from_syscall) {
        return;
    }
    const fs_sync_start_t start = {
        .started_ns = bpf_ktime_get_ns(),
        .s_dev = file ? file_s_dev(file) : 0,
        .type = datasync ? fs_sync_type_fdatasync : fs_sync_type_fsync,
    };
    bpf_map_update_elem(&fs_sync_start, &pid_tgid, &start, BPF_ANY);
}

static __always_inline void fs_sync_returned(const s32 ret, const bool from_syscall) {
    const u64 pid_tgid = bpf_get_current_pid_tgid();
    const fs_sync_start_t *start = bpf_map_lookup_elem(&fs_sync_start, &pid_tgid);
    if (!start || start->from_syscall != from_syscall) {
        return;
    }
    const u64 latency_ns = bpf_ktime_get_ns() - start->started_ns;
    struct cgroup *cgrp = current_io_cgroup();
    const fs_sync_key_t key = {
        .cgroup_id = BPF_CORE_READ(cgrp, kn, id),
        .s_dev = start->s_dev,
        .status = fs_sync_status(ret),
        .type = start->type,
    };
    bpf_map_delete_elem(&fs_sync_start, &pid_tgid);
    if (!fs_sync_attempted(ret)) {
        return;
    }

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

// The sync system calls. They are probed besides the kernel functions that sync files, because
// kernel builds inline some of these functions into the system calls: e.g. fdatasync(2) never
// calls vfs_fsync_range on some 5.x kernels, and no system call does on Linux 7.2.
SEC("kprobe/sys_fsync")
int BPF_KPROBE(obi_stats_kprobe_sys_fsync) {
    syscall_sync_started(fs_sync_type_fsync, file_s_dev(current_file(syscall_fd(ctx))));
    return 0;
}

SEC("kprobe/sys_fdatasync")
int BPF_KPROBE(obi_stats_kprobe_sys_fdatasync) {
    syscall_sync_started(fs_sync_type_fdatasync, file_s_dev(current_file(syscall_fd(ctx))));
    return 0;
}

SEC("kprobe/sys_syncfs")
int BPF_KPROBE(obi_stats_kprobe_sys_syncfs) {
    syscall_sync_started(fs_sync_type_syncfs, file_s_dev(current_file(syscall_fd(ctx))));
    return 0;
}

SEC("kprobe/sys_sync_file_range")
int BPF_KPROBE(obi_stats_kprobe_sys_sync_file_range) {
    syscall_sync_started(fs_sync_type_sync_file_range, file_s_dev(current_file(syscall_fd(ctx))));
    return 0;
}

SEC("kprobe/sys_sync")
int BPF_KPROBE(obi_stats_kprobe_sys_sync) {
    (void)ctx;
    syscall_sync_started(fs_sync_type_sync, 0);
    return 0;
}

// the return probe of every sync system call
SEC("kretprobe/sys_sync")
int BPF_KRETPROBE(obi_stats_kretprobe_sys_fs_sync, long ret) {
    (void)ctx;
    fs_sync_returned(ret, true);
    return 0;
}

// vfs_fsync_range serves fsync(2), fdatasync(2), O_SYNC and O_DSYNC writes, msync(2) with
// MS_SYNC, and their io_uring equivalents.
SEC("kprobe/vfs_fsync_range")
int BPF_KPROBE(
    obi_stats_kprobe_vfs_fsync_range, struct file *file, loff_t start, loff_t end, int datasync) {
    (void)ctx;
    (void)start;
    (void)end;
    function_sync_started(datasync, file);
    return 0;
}

SEC("kretprobe/vfs_fsync_range")
int BPF_KRETPROBE(obi_stats_kretprobe_vfs_fsync_range, int ret) {
    (void)ctx;
    fs_sync_returned(ret, false);
    return 0;
}

// do_fsync serves fsync(2) and fdatasync(2). It is a function of its own since Linux 6.12 only:
// userspace attaches these probes when the kernel has it.
SEC("kprobe/do_fsync")
int BPF_KPROBE(obi_stats_kprobe_do_fsync, unsigned int fd, int datasync) {
    (void)ctx;
    function_sync_started(datasync, current_file(fd));
    return 0;
}

SEC("kretprobe/do_fsync")
int BPF_KRETPROBE(obi_stats_kretprobe_do_fsync, int ret) {
    (void)ctx;
    fs_sync_returned(ret, false);
    return 0;
}
