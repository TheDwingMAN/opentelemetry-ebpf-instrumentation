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

// Set by userspace when the file sync metric reports an attribute that needs the cgroup the sync is
// charged to (the container and Kubernetes attributes), or the filesystem of the synced file.
// Otherwise the probes don't read them, which saves a few kernel reads per sync.
volatile const bool fs_sync_read_cgroup;
volatile const bool fs_sync_read_filesystem;

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

// The flags of sync_file_range(2), its fourth argument, from the pt_regs of the caller. System
// calls get their fourth argument in r10 on x86-64, because SYSCALL overwrites rcx.
static __always_inline u32 syscall_sync_file_range_flags(struct pt_regs *ctx) {
    struct pt_regs *regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
    u32 flags = 0;
#if defined(__TARGET_ARCH_x86)
    bpf_probe_read_kernel(&flags, sizeof(flags), &regs->r10);
#else
    bpf_probe_read_kernel(&flags, sizeof(flags), (void *)&PT_REGS_PARM4(regs));
#endif
    return flags;
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

// Starts measuring a sync system call of the current thread that gets a file descriptor as its
// first argument
static __always_inline void fd_syscall_sync_started(struct pt_regs *ctx,
                                                    const enum fs_sync_type type) {
    const u32 s_dev = fs_sync_read_filesystem ? file_s_dev(current_file(syscall_fd(ctx))) : 0;
    syscall_sync_started(type, s_dev);
}

// A sync system call in progress for longer is considered stale: its kretprobe was missed, and it
// must not keep the syncs of its thread outside of system calls from being measured.
enum { k_fs_sync_syscall_stale_ns = 10ULL * 60 * 1000 * 1000 * 1000 };

// Whether a sync system call of the current thread is being measured: the kernel functions it
// calls leave it alone
static __always_inline bool in_measured_syscall(const u64 pid_tgid, const u64 now) {
    const fs_sync_start_t *current = bpf_map_lookup_elem(&fs_sync_start, &pid_tgid);
    return current && current->from_syscall &&
           now - current->started_ns < k_fs_sync_syscall_stale_ns;
}

// Starts measuring a file sync that a kernel function does outside of the sync system calls:
// O_SYNC and O_DSYNC writes, msync(2), io_uring, the NFS server... File syncs nest when a
// stacked filesystem, like overlayfs, syncs the file below: the innermost call is measured,
// once, and a thread whose kretprobe was missed recovers on its next sync.
static __always_inline void
function_sync_started(const u64 pid_tgid, const u64 now, const int datasync, const u32 s_dev) {
    const fs_sync_start_t start = {
        .started_ns = now,
        .s_dev = s_dev,
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
    struct cgroup *cgrp = fs_sync_read_cgroup ? current_io_cgroup() : 0;
    const fs_sync_key_t key = {
        .cgroup_id = cgroup_id_of(cgrp),
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
    fd_syscall_sync_started(ctx, fs_sync_type_fsync);
    return 0;
}

SEC("kprobe/sys_fdatasync")
int BPF_KPROBE(obi_stats_kprobe_sys_fdatasync) {
    fd_syscall_sync_started(ctx, fs_sync_type_fdatasync);
    return 0;
}

SEC("kprobe/sys_syncfs")
int BPF_KPROBE(obi_stats_kprobe_sys_syncfs) {
    fd_syscall_sync_started(ctx, fs_sync_type_syncfs);
    return 0;
}

SEC("kprobe/sys_sync_file_range")
int BPF_KPROBE(obi_stats_kprobe_sys_sync_file_range) {
    if (!sync_file_range_waits(syscall_sync_file_range_flags(ctx))) {
        // a thread is in one system call at a time: any start it still has is stale
        const u64 pid_tgid = bpf_get_current_pid_tgid();
        bpf_map_delete_elem(&fs_sync_start, &pid_tgid);
        return 0;
    }
    fd_syscall_sync_started(ctx, fs_sync_type_sync_file_range);
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
    const u64 pid_tgid = bpf_get_current_pid_tgid();
    const u64 now = bpf_ktime_get_ns();
    if (in_measured_syscall(pid_tgid, now)) {
        return 0;
    }
    const u32 s_dev = fs_sync_read_filesystem && file ? file_s_dev(file) : 0;
    function_sync_started(pid_tgid, now, datasync, s_dev);
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
    const u64 pid_tgid = bpf_get_current_pid_tgid();
    const u64 now = bpf_ktime_get_ns();
    // checked before the file is looked up: do_fsync mostly runs inside fsync(2) and fdatasync(2)
    if (in_measured_syscall(pid_tgid, now)) {
        return 0;
    }
    const u32 s_dev = fs_sync_read_filesystem ? file_s_dev(current_file(fd)) : 0;
    function_sync_started(pid_tgid, now, datasync, s_dev);
    return 0;
}

SEC("kretprobe/do_fsync")
int BPF_KRETPROBE(obi_stats_kretprobe_do_fsync, int ret) {
    (void)ctx;
    fs_sync_returned(ret, false);
    return 0;
}
