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

// Set by userspace when the workloads of the syncs are reported: otherwise the verifier leaves the
// cgroup reads out
volatile const bool fs_sync_read_cgroup;

// Force structs into the ELF for automatic creation of Golang struct
const fs_sync_key_t *unused_fs_sync_key __attribute__((unused));
const fs_sync_accum_t *unused_fs_sync_accum __attribute__((unused));

SCRATCH_MEM_TYPED(fs_sync_accum_init, fs_sync_accum_t)

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

// The flags of sync_file_range(2), its fourth argument, from the registers of the system call:
// x86-64 passes it in r10, as SYSCALL overwrites rcx
static __always_inline u32 syscall_sync_file_range_flags(const struct pt_regs *regs) {
    u32 flags = 0;
#ifdef __TARGET_ARCH_x86
    bpf_probe_read_kernel(&flags, sizeof(flags), &regs->r10);
#else
    bpf_probe_read_kernel(&flags, sizeof(flags), (const void *)&PT_REGS_PARM4(regs));
#endif
    return flags;
}

static __always_inline void syscall_sync_started(const enum fs_sync_type type) {
    const u64 pid_tgid = bpf_get_current_pid_tgid();
    const fs_sync_start_t start = {
        .started_ns = bpf_ktime_get_ns(),
        .type = type,
        .from_syscall = 1,
    };
    bpf_map_update_elem(&fs_sync_start, &pid_tgid, &start, BPF_ANY);
}

static __always_inline void sync_file_range_started(const struct pt_regs *regs) {
    if (sync_file_range_waits(syscall_sync_file_range_flags(regs))) {
        syscall_sync_started(fs_sync_type_sync_file_range);
        return;
    }
    // a thread is in one system call at a time: a start that it still has is stale
    const u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&fs_sync_start, &pid_tgid);
}

// A sync system call in progress for longer is stale: a kretprobe misses the returns of the calls
// beyond a number in progress at once. It is above the largest bound of the histogram, 60 s: a
// longer call is measured by the kernel function that it calls, which then takes its start over.
enum { k_fs_sync_syscall_stale_ns = 2ULL * 60 * 1000 * 1000 * 1000 };

static __always_inline bool in_measured_syscall(const u64 pid_tgid, const u64 now_ns) {
    const fs_sync_start_t *current = bpf_map_lookup_elem(&fs_sync_start, &pid_tgid);
    return current && current->from_syscall &&
           now_ns - current->started_ns < k_fs_sync_syscall_stale_ns;
}

// A kernel function syncs outside the sync system calls for O_SYNC and O_DSYNC writes, msync(2),
// io_uring, the NFS server... Syncs nest when a stacked filesystem, such as overlayfs, syncs the
// file below: the innermost one is measured.
static __always_inline void function_sync_started(const int datasync) {
    const u64 pid_tgid = bpf_get_current_pid_tgid();
    const u64 now_ns = bpf_ktime_get_ns();
    if (in_measured_syscall(pid_tgid, now_ns)) {
        return;
    }
    const fs_sync_start_t start = {
        .started_ns = now_ns,
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
    const u64 now_ns = bpf_ktime_get_ns();
    const u64 latency_ns = now_ns > start->started_ns ? now_ns - start->started_ns : 0;
    const enum fs_sync_type type = start->type;
    bpf_map_delete_elem(&fs_sync_start, &pid_tgid);
    if (!fs_sync_attempted(ret)) {
        return;
    }

    struct cgroup *cgrp = fs_sync_read_cgroup ? current_io_cgroup() : 0;
    const fs_sync_key_t key = {
        .cgroup_id = cgroup_id_of(cgrp),
        // a sync returns 0 or a negative errno, as block_rq_complete before Linux 5.16
        .status = disk_status_code((u64)ret, false),
        .type = type,
    };
    fs_sync_accum_t *accum = lookup_or_init_fs_sync_accum(&key);
    if (!accum) {
        return;
    }
    if (cgrp) {
        record_cgroup_name(key.cgroup_id, cgrp);
    }
    const u32 bucket = disk_latency_bucket(disk_latency_bounds_ns, latency_ns);
    __sync_fetch_and_add(&accum->latency_count[bucket], 1);
    __sync_fetch_and_add(&accum->latency_sum_ns, latency_ns);
}

// The sync system calls are probed besides the kernel functions that sync files, as kernel builds
// inline some of these functions into the system calls: fdatasync(2) never calls vfs_fsync_range on
// some 5.x kernels, and no system call does on Linux 7.2. The system call wrappers get the
// registers of the system call as their argument.
SEC("kprobe/sys_fsync")
int BPF_KPROBE(obi_stats_kprobe_sys_fsync) {
    (void)ctx;
    syscall_sync_started(fs_sync_type_fsync);
    return 0;
}

SEC("kprobe/sys_fdatasync")
int BPF_KPROBE(obi_stats_kprobe_sys_fdatasync) {
    (void)ctx;
    syscall_sync_started(fs_sync_type_fdatasync);
    return 0;
}

SEC("kprobe/sys_syncfs")
int BPF_KPROBE(obi_stats_kprobe_sys_syncfs) {
    (void)ctx;
    syscall_sync_started(fs_sync_type_syncfs);
    return 0;
}

SEC("kprobe/sys_sync_file_range")
int BPF_KPROBE(obi_stats_kprobe_sys_sync_file_range, const struct pt_regs *regs) {
    (void)ctx;
    sync_file_range_started(regs);
    return 0;
}

// the return probe of the four system calls above
SEC("kretprobe/sys_fsync")
int BPF_KRETPROBE(obi_stats_kretprobe_sync_syscall, long ret) {
    (void)ctx;
    fs_sync_returned(ret, true);
    return 0;
}

// sync(2) is probed at ksys_sync, which it calls, as the BTF of most kernels has no function for
// its system call wrapper, which a tracing program needs. ksys_sync also syncs before a suspend.
SEC("kprobe/ksys_sync")
int BPF_KPROBE(obi_stats_kprobe_ksys_sync) {
    (void)ctx;
    syscall_sync_started(fs_sync_type_sync);
    return 0;
}

// ksys_sync returns no value
SEC("kretprobe/ksys_sync")
int BPF_KRETPROBE(obi_stats_kretprobe_ksys_sync) {
    (void)ctx;
    fs_sync_returned(0, true);
    return 0;
}

// vfs_fsync_range serves fsync(2), fdatasync(2), O_SYNC and O_DSYNC writes, msync(2) with MS_SYNC,
// and their io_uring equivalents
SEC("kprobe/vfs_fsync_range")
int BPF_KPROBE(
    obi_stats_kprobe_vfs_fsync_range, struct file *file, loff_t start, loff_t end, int datasync) {
    (void)ctx;
    (void)file;
    (void)start;
    (void)end;
    function_sync_started(datasync);
    return 0;
}

SEC("kretprobe/vfs_fsync_range")
int BPF_KRETPROBE(obi_stats_kretprobe_vfs_fsync_range, int ret) {
    (void)ctx;
    fs_sync_returned(ret, false);
    return 0;
}

// vfs_fsync serves the flushes of the loop devices, the SMB server and the other kernel callers
// that sync a whole file. Some kernels, as Linux 5.8, inline vfs_fsync_range into it.
SEC("kprobe/vfs_fsync")
int BPF_KPROBE(obi_stats_kprobe_vfs_fsync, struct file *file, int datasync) {
    (void)ctx;
    (void)file;
    function_sync_started(datasync);
    return 0;
}

SEC("kretprobe/vfs_fsync")
int BPF_KRETPROBE(obi_stats_kretprobe_vfs_fsync, int ret) {
    (void)ctx;
    fs_sync_returned(ret, false);
    return 0;
}

// do_fsync serves fsync(2) and fdatasync(2), as a function of its own from Linux 6.12 and on RHEL 8
SEC("kprobe/do_fsync")
int BPF_KPROBE(obi_stats_kprobe_do_fsync, unsigned int fd, int datasync) {
    (void)ctx;
    (void)fd;
    function_sync_started(datasync);
    return 0;
}

SEC("kretprobe/do_fsync")
int BPF_KRETPROBE(obi_stats_kretprobe_do_fsync, int ret) {
    (void)ctx;
    fs_sync_returned(ret, false);
    return 0;
}

// The same probes as fentry and fexit programs, which userspace attaches instead where the kernel
// can: an fexit program, unlike a kretprobe, sees the returns of any number of calls in progress at
// once, as when many threads sync during a storage stall. Userspace names the system calls with
// the prefix of their kernel functions, e.g. __x64_sys_fsync. An fentry program gets the arguments
// of the function in its context, and an fexit program the arguments, then the return value:
enum {
    // the system call wrappers get the registers of the system call
    k_syscall_regs_arg = 0,
    k_syscall_ret = 1,
    // vfs_fsync_range(file, start, end, datasync)
    k_vfs_fsync_range_datasync_arg = 3,
    k_vfs_fsync_range_ret = 4,
    // vfs_fsync(file, datasync) and do_fsync(fd, datasync)
    k_fsync_datasync_arg = 1,
    k_fsync_ret = 2,
};

SEC("fentry/sys_fsync")
int obi_stats_fentry_sys_fsync(const u64 *ctx) {
    (void)ctx;
    syscall_sync_started(fs_sync_type_fsync);
    return 0;
}

SEC("fexit/sys_fsync")
int obi_stats_fexit_sys_fsync(const u64 *ctx) {
    fs_sync_returned((s32)ctx[k_syscall_ret], true);
    return 0;
}

SEC("fentry/sys_fdatasync")
int obi_stats_fentry_sys_fdatasync(const u64 *ctx) {
    (void)ctx;
    syscall_sync_started(fs_sync_type_fdatasync);
    return 0;
}

SEC("fexit/sys_fdatasync")
int obi_stats_fexit_sys_fdatasync(const u64 *ctx) {
    fs_sync_returned((s32)ctx[k_syscall_ret], true);
    return 0;
}

SEC("fentry/sys_syncfs")
int obi_stats_fentry_sys_syncfs(const u64 *ctx) {
    (void)ctx;
    syscall_sync_started(fs_sync_type_syncfs);
    return 0;
}

SEC("fexit/sys_syncfs")
int obi_stats_fexit_sys_syncfs(const u64 *ctx) {
    fs_sync_returned((s32)ctx[k_syscall_ret], true);
    return 0;
}

SEC("fentry/sys_sync_file_range")
int obi_stats_fentry_sys_sync_file_range(const u64 *ctx) {
    sync_file_range_started((const struct pt_regs *)ctx[k_syscall_regs_arg]);
    return 0;
}

SEC("fexit/sys_sync_file_range")
int obi_stats_fexit_sys_sync_file_range(const u64 *ctx) {
    fs_sync_returned((s32)ctx[k_syscall_ret], true);
    return 0;
}

SEC("fentry/ksys_sync")
int obi_stats_fentry_ksys_sync(const u64 *ctx) {
    (void)ctx;
    syscall_sync_started(fs_sync_type_sync);
    return 0;
}

// ksys_sync returns no value
SEC("fexit/ksys_sync")
int obi_stats_fexit_ksys_sync(const u64 *ctx) {
    (void)ctx;
    fs_sync_returned(0, true);
    return 0;
}

SEC("fentry/vfs_fsync_range")
int obi_stats_fentry_vfs_fsync_range(const u64 *ctx) {
    function_sync_started((int)ctx[k_vfs_fsync_range_datasync_arg]);
    return 0;
}

SEC("fexit/vfs_fsync_range")
int obi_stats_fexit_vfs_fsync_range(const u64 *ctx) {
    fs_sync_returned((s32)ctx[k_vfs_fsync_range_ret], false);
    return 0;
}

SEC("fentry/vfs_fsync")
int obi_stats_fentry_vfs_fsync(const u64 *ctx) {
    function_sync_started((int)ctx[k_fsync_datasync_arg]);
    return 0;
}

SEC("fexit/vfs_fsync")
int obi_stats_fexit_vfs_fsync(const u64 *ctx) {
    fs_sync_returned((s32)ctx[k_fsync_ret], false);
    return 0;
}

SEC("fentry/do_fsync")
int obi_stats_fentry_do_fsync(const u64 *ctx) {
    function_sync_started((int)ctx[k_fsync_datasync_arg]);
    return 0;
}

SEC("fexit/do_fsync")
int obi_stats_fexit_do_fsync(const u64 *ctx) {
    fs_sync_returned((s32)ctx[k_fsync_ret], false);
    return 0;
}
