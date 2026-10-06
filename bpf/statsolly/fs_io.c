// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_core_read.h>
#include <bpfcore/bpf_tracing.h>

#include <logger/bpf_dbg.h>

#include <statsolly/fs_io.h>
#include <statsolly/hist.h>
#include <statsolly/types.h>
#include <statsolly/maps/stats_events.h>
#include <statsolly/maps/fs_start.h>
#include <statsolly/maps/fs_dev_filter.h>
#include <statsolly/maps/fs_io_accum.h>

// Load-time constants, the same in every filesystem collection.
//
// fs_emit_mode is an enum fs_emit_kind: per-event ring buffer records, or
// kernel-side aggregation into fs_io_accum (fs_io_accum_exp when fs_hist_exp
// is set), with fs_bounds_ns as the histogram bounds: the explicit layout's
// first 32, or the exponential layout's 128, padded with U64_MAX.
volatile const u8 fs_emit_mode = fs_emit_ringbuf;
volatile const u8 fs_hist_exp = 0;
volatile const u64 fs_bounds_ns[k_stat_hist_exp_max_bounds];

// fs_task_btf lets the fentry/fexit programs call bpf_get_current_task_btf
// and keep their start in task storage (fs_start_task); without it (kernels
// before 5.11, or whose tracing programs may not use task storage) they use
// fs_start, as the kprobe programs always do.
volatile const u8 fs_task_btf = 0;

// Force emitting these enums into the ELF so bpf2go generates their Go constants
const enum fs_emit_kind *unused_fs_emit_kind __attribute__((unused));
const enum fs_drop_reason *unused_fs_drop_reason __attribute__((unused));

static __always_inline void fs_count_drop(const enum fs_drop_reason reason) {
    const u32 key = reason;
    u64 *const n = bpf_map_lookup_elem(&fs_drops, &key);
    if (n) {
        __sync_fetch_and_add(n, 1);
    }
}

// fs_use_task_storage reports whether a program keeps its start in task
// storage: only fentry/fexit programs (tracing), and only where allowed.
static __always_inline bool fs_use_task_storage(const bool tracing) {
    return tracing && fs_task_btf;
}

// fs_probe_entry_file records the start of an operation on file. tracing
// selects fentry-mode task storage for the start (fs_start_task) over the
// kprobe-mode fs_start hash map; it does not by itself say file can be
// dereferenced directly. trusted_file is the separate, narrower claim that
// matters for that: file is a BTF pointer the verifier has followed from a
// trusted root the whole way (a fentry/fexit program's own BTF argument, or
// a CO-RE field walk from one), so direct loads are verifier-safe. The two
// usually coincide (every per-filesystem file_operations probe is trusted
// exactly when it runs in fentry mode, which is why every caller below
// passes tracing for both), but fs_probe_entry_generic's syncfs and
// sync_file_range callers break that pattern: their file (current_file_fdt,
// below) came from bpf_probe_read_kernel of an fd-table slot, which the
// verifier treats as an opaque scalar with no provenance regardless of the
// program type, so they pass trusted_file=false even while tracing is true
// for their fentry/fexit task-storage fast path. Confirmed against the real
// verifier: reusing tracing for both fields syncfs/sync_file_range with
// "R7 invalid mem access 'scalar'" on the direct file->f_inode load.
//
// Direct loads save one bpf_probe_read_kernel call per hop and are as
// portable as BPF_CORE_READ when trusted_file holds: vmlinux.h marks every
// struct preserve_access_index, so each hop gets the same CO-RE relocation,
// and the verifier types each load from a BTF pointer on its own
// (btf_struct_access, which also enters embedded structs such as f_path and
// ns), so chain depth does not matter. The chains here resolve against the
// RHEL 9.0 (5.14.0-70.el9) and 9.8 (5.14.0-687.el9) BTF, and the 9.0 source
// already has that nested walk.
static __always_inline void fs_probe_entry_file(const struct file *const file,
                                                const enum fs_type fs,
                                                const enum fs_op op,
                                                const bool tracing,
                                                const bool trusted_file) {
    u32 s_dev;
    if (trusted_file) {
        s_dev = file->f_inode->i_sb->s_dev;
    } else {
        s_dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev);
    }

    // ext4/xfs/btrfs also back the node's own root filesystem and every
    // container's writable layer, so only record when the device is a known
    // PV-backed mount (fs_dev_filter, populated from userspace). Network
    // filesystems are never used for the node's own root, so they stay
    // unfiltered.
    const bool is_local_fs = fs == fs_type_ext4 || fs == fs_type_xfs || fs == fs_type_btrfs;
    if (is_local_fs && !bpf_map_lookup_elem(&fs_dev_filter, &s_dev)) {
        return;
    }

    // O_SYNC/O_DSYNC writes call the filesystem's fsync file_operation on the
    // same thread as the write (ext4_file_write_iter -> generic_write_sync ->
    // ext4_sync_file; same for xfs, nfs, ceph, fuse). Without this check, the
    // nested fsync's entry would overwrite the outer write's start and its
    // exit would take it, so the write would record nothing. Track nesting
    // depth instead and let only the outermost exit record (fs_start_nest).
    const u64 now = bpf_ktime_get_ns();
    struct fs_start_val *cur;
    u64 id = 0;
    if (fs_use_task_storage(tracing)) {
        cur = bpf_task_storage_get(
            &fs_start_task, bpf_get_current_task_btf(), 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
        if (!cur) {
            fs_count_drop(fs_drop_start);
            return;
        }
    } else {
        id = bpf_get_current_pid_tgid();
        cur = bpf_map_lookup_elem(&fs_start, &id);
    }
    if (fs_start_nest(cur, now)) {
        return;
    }

    u64 root_ino;
    if (trusted_file) {
        root_ino = file->f_path.mnt->mnt_root->d_inode->i_ino;
    } else {
        root_ino = BPF_CORE_READ(file, f_path.mnt, mnt_root, d_inode, i_ino);
    }

    if (fs_use_task_storage(tracing)) {
        // The thread's own storage: no other thread writes it.
        cur->ts = now;
        cur->root_ino = root_ino;
        cur->s_dev = s_dev;
        cur->fs = fs;
        cur->op = op;
        cur->depth = 0;
        return;
    }

    struct fs_start_val val = {};
    val.ts = now;
    val.root_ino = root_ino;
    val.s_dev = s_dev;
    val.fs = fs;
    val.op = op;
    val.depth = 0;
    if (bpf_map_update_elem(&fs_start, &id, &val, BPF_ANY)) {
        fs_count_drop(fs_drop_start);
    }
}

// Every caller below hands fs_probe_entry_file a file it reached by a
// trusted CO-RE walk (a BTF argument of this very program, or a CO-RE field
// of one), so trusted_file is tracing here: true (direct loads) for every
// per-filesystem file_operations probe's fentry/fexit variant, false
// (BPF_CORE_READ) for its kprobe/kretprobe fallback. fs_probe_entry_generic
// below is the one caller where that equivalence does not hold.
static __always_inline void fs_probe_entry_file_tracing(const struct file *const file,
                                                        const enum fs_type fs,
                                                        const enum fs_op op) {
    fs_probe_entry_file(file, fs, op, true, true);
}

static __always_inline void fs_probe_entry_file_kprobe(const struct file *const file,
                                                       const enum fs_type fs,
                                                       const enum fs_op op) {
    fs_probe_entry_file(file, fs, op, false, false);
}

static __always_inline void
fs_probe_entry_tracing(const struct kiocb *const iocb, const enum fs_type fs, const enum fs_op op) {
    fs_probe_entry_file(iocb->ki_filp, fs, op, true, true);
}

static __always_inline void
fs_probe_entry_kprobe(const struct kiocb *const iocb, const enum fs_type fs, const enum fs_op op) {
    const struct file *const file = BPF_CORE_READ(iocb, ki_filp);
    fs_probe_entry_file(file, fs, op, false, false);
}

// fs_start_take moves the thread's outermost start into out, and reports
// false for no start or a nested exit (fs_start_unnest).
static __always_inline bool
fs_start_take(struct fs_start_val *out, const u64 id, const bool tracing) {
    if (fs_use_task_storage(tracing)) {
        struct fs_start_val *const cur =
            bpf_task_storage_get(&fs_start_task, bpf_get_current_task_btf(), 0, 0);
        if (!cur || cur->ts == 0 || fs_start_unnest(cur)) {
            return false;
        }
        *out = *cur;
        cur->ts = 0;
        return true;
    }

    struct fs_start_val *const cur = bpf_map_lookup_elem(&fs_start, &id);
    if (!cur || fs_start_unnest(cur)) {
        return false;
    }
    *out = *cur;
    bpf_map_delete_elem(&fs_start, &id);
    return true;
}

// fs_current_pid_ns returns the PID namespace of the calling thread, as
// task_pid (pid/pid_helpers.h) reads it, with direct loads from the task
// BTF pointer where available (see fs_probe_entry_file).
static __always_inline u32 fs_current_pid_ns(const bool tracing) {
    if (fs_use_task_storage(tracing)) {
        const struct task_struct *const task = bpf_get_current_task_btf();
        return task->nsproxy->pid_ns_for_children->ns.inum;
    }
    const struct task_struct *const task = (struct task_struct *)bpf_get_current_task();
    return BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
}

// fs_accum_get returns the value of key in map, creating it zeroed first, or
// NULL when the map is full.
static __always_inline void *fs_accum_get(void *const map,
                                          const struct fs_io_accum_key *const key) {
    void *v = bpf_map_lookup_elem(map, key);
    if (v) {
        return v;
    }
    const u32 zero_key = 0;
    const void *const zero = bpf_map_lookup_elem(&fs_accum_zero, &zero_key);
    if (!zero) {
        return NULL;
    }
    // EEXIST when another CPU created it meanwhile: the lookup finds it.
    bpf_map_update_elem(map, key, zero, BPF_NOEXIST);
    return bpf_map_lookup_elem(map, key);
}

// fs_aggregate adds a completed operation to fs_io_accum (fs_io_accum_exp).
static __always_inline void fs_aggregate(const struct fs_start_val *const start,
                                         const u64 latency,
                                         const long ret,
                                         const u32 pid_ns,
                                         const u32 tgid) {
    struct fs_io_accum_key key;
    fs_accum_key_init(&key, bpf_get_current_cgroup_id(), start, pid_ns, ret);
    const u64 bytes = ret > 0 ? (u64)ret : 0;

    if (fs_hist_exp) {
        struct fs_io_accum_exp_val *const v = fs_accum_get(&fs_io_accum_exp, &key);
        if (!v) {
            fs_count_drop(fs_drop_accum_full);
            return;
        }
        __sync_fetch_and_add(&v->sum_ns, latency);
        if (bytes) {
            __sync_fetch_and_add(&v->bytes, bytes);
        }
        stat_hist_exp_add(v->bkt, stat_hist_exp_idx(fs_bounds_ns, latency));
        if (v->sample_tgid != tgid) {
            v->sample_tgid = tgid;
        }
        return;
    }

    struct fs_io_accum_val *const v = fs_accum_get(&fs_io_accum, &key);
    if (!v) {
        fs_count_drop(fs_drop_accum_full);
        return;
    }
    __sync_fetch_and_add(&v->sum_ns, latency);
    if (bytes) {
        __sync_fetch_and_add(&v->bytes, bytes);
    }
    stat_hist_add(v->bkt, stat_hist_idx(fs_bounds_ns, latency));
    if (v->sample_tgid != tgid) {
        v->sample_tgid = tgid;
    }
}

static __always_inline void fs_probe_exit(const long ret, const bool tracing) {
    const u64 id = bpf_get_current_pid_tgid();
    struct fs_start_val start;
    if (!fs_start_take(&start, id, tracing)) {
        return;
    }
    const u64 latency = bpf_ktime_get_ns() - start.ts;
    if (!fs_ret_recorded(start.op, ret)) {
        return;
    }

    const u32 host_pid = (u32)(id >> 32);
    const u32 pid_ns = fs_current_pid_ns(tracing);

    if (fs_emit_mode == fs_emit_agg) {
        fs_aggregate(&start, latency, ret, pid_ns, host_pid);
        return;
    }

    fs_io_t *const se = bpf_ringbuf_reserve(&stats_events, sizeof(*se), 0);
    if (!se) {
        bpf_d_printk("fs_io: stats_events ring buffer full, dropping event");
        return;
    }

    se->flags = k_stat_type_fs_io;
    se->fs = start.fs;
    // fs_start_val.op is a plain u8 (fs_io_accum_key is hashed as raw
    // bytes, and fs_start_val mirrors its field types), but every writer
    // of it (fs_probe_entry_file, fs_probe_entry_sync) stores one of enum
    // fs_op's own constants, so this is never out of range; the analyzer
    // cannot see that across the map/task-storage round trip.
    // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
    se->op = start.op;
    se->_pad[0] = 0;
    se->s_dev = start.s_dev;
    se->host_pid = host_pid;
    se->pid_ns = pid_ns;
    se->latency_ns = latency;
    se->bytes = ret > 0 ? (u64)ret : 0;
    se->error = ret < 0 ? (s32)ret : 0;
    se->_pad2[0] = 0;
    se->_pad2[1] = 0;
    se->_pad2[2] = 0;
    se->_pad2[3] = 0;
    se->root_ino = start.root_ino;

    bpf_ringbuf_submit(se, stats_events_flags());
}

static __always_inline void fs_probe_exit_tracing(const long ret) {
    fs_probe_exit(ret, true);
}

static __always_inline void fs_probe_exit_kprobe(const long ret) {
    fs_probe_exit(ret, false);
}

// current_file_* turn a sync syscall's file descriptor argument into the
// struct file fs_probe_entry_generic wants, so syncfs and sync_file_range
// get the same PV filter, root_ino and pod attribution as read/write/fsync.
// Ported from v2's current_file (bpf/statsolly/k_fsync.c:45-55). BPF runs
// under RCU, so walking the live fdtable is safe.
// current_file_fdt reads the struct file at index fd of a thread's fd table,
// or NULL if fd is out of range (a bad caller-supplied descriptor is
// normal, not a verifier concern). fdt->fd is a plain kernel pointer to a
// dynamically sized array, not a fixed-size struct member, so the final read
// goes through bpf_probe_read_kernel even in tracing mode.
static __always_inline struct file *
current_file_fdt(const u32 max_fds, struct file *const *const fds, const u32 fd) {
    if (fd >= max_fds) {
        return NULL;
    }
    struct file *file = NULL;
    bpf_probe_read_kernel(&file, sizeof(file), fds + fd);
    return file;
}

static __always_inline struct file *current_file_tracing(const u32 fd) {
    const struct task_struct *const task = bpf_get_current_task_btf();
    const struct fdtable *const fdt = task->files->fdt;
    if (!fdt) {
        return NULL;
    }
    return current_file_fdt(fdt->max_fds, fdt->fd, fd);
}

static __always_inline struct file *current_file_kprobe(const u32 fd) {
    const struct task_struct *const task = (struct task_struct *)bpf_get_current_task();
    const struct fdtable *const fdt = BPF_CORE_READ(task, files, fdt);
    if (!fdt) {
        return NULL;
    }
    return current_file_fdt(BPF_CORE_READ(fdt, max_fds), BPF_CORE_READ(fdt, fd), fd);
}

// syscall_arg1/syscall_arg4 read the 1st and 4th arguments of the real
// syscall from regs: the struct pt_regs a syscall wrapper (__x64_sys_*,
// __arm64_sys_*) receives as its own sole parameter under
// CONFIG_ARCH_HAS_SYSCALL_WRAPPER. fentry gets that pointer as its one BTF
// argument; a kprobe on the wrapper gets it the same way BPF_KPROBE always
// extracts a declared argument, from PT_REGS_PARM1 of its own ctx. Either
// way regs is read with BPF_CORE_READ, like every other kernel pointer this
// file was not handed as a tracing program's own BTF argument.
static __always_inline u32 syscall_arg1(const struct pt_regs *const regs) {
    return (u32)PT_REGS_PARM1_CORE(regs);
}

// The 4th argument of a raw x86_64 syscall is read from r10, not rcx
// (PT_REGS_PARM4_CORE): the SYSCALL instruction itself clobbers rcx, so the
// kernel's raw syscall ABI moves the 4th argument to r10. arm64 has no such
// quirk: PT_REGS_PARM4_CORE already reads the right register there.
static __always_inline u32 syscall_arg4(const struct pt_regs *const regs) {
#if defined(bpf_target_x86)
    return (u32)BPF_CORE_READ(regs, r10);
#else
    return (u32)PT_REGS_PARM4_CORE(regs);
#endif
}

// fs_probe_entry_generic starts measuring a syncfs(2) or sync_file_range(2)
// call: these have no fixed filesystem (unlike the per-filesystem
// read/write/fsync probes, 2.4), so the filesystem is classified from the
// file's own superblock. fs_type_unknown (overlay, tmpfs, proc, ...) is not
// a filesystem this spec tracks at all, unlike the per-filesystem probes'
// fs_dev_filter check, which only excludes a *tracked* local filesystem
// (ext4/xfs/btrfs) when it is not PV-backed: without this check every
// container's overlay rootfs sync would create an unbounded, unfiltered key
// (the v2 review's Q4).
//
// file is never a trusted pointer here, in fentry mode or not: it came from
// current_file_fdt's bpf_probe_read_kernel of an fd-table slot (an untrusted
// scalar to the verifier, unlike a file_operations probe's own BTF
// argument), so every field access goes through BPF_CORE_READ regardless of
// tracing (fs_probe_entry_file's trusted_file=false) -- confirmed against
// the real verifier, which rejects the direct-load form with "R7 invalid
// mem access 'scalar'".
static __always_inline void
fs_probe_entry_generic(const struct file *const file, const enum fs_op op, const bool tracing) {
    const u64 magic = BPF_CORE_READ(file, f_inode, i_sb, s_magic);
    const enum fs_type fs = fs_type_from_sb(magic);
    if (fs == fs_type_unknown) {
        return;
    }
    fs_probe_entry_file(file, fs, op, tracing, false);
}

static __always_inline void fs_probe_entry_syncfs(const struct pt_regs *const regs,
                                                  const bool tracing) {
    const u32 fd = syscall_arg1(regs);
    const struct file *const file = tracing ? current_file_tracing(fd) : current_file_kprobe(fd);
    if (!file) {
        return;
    }
    fs_probe_entry_generic(file, fs_op_syncfs, tracing);
}

static __always_inline void fs_probe_entry_sync_file_range(const struct pt_regs *const regs,
                                                           const bool tracing) {
    if (!sync_file_range_waits(syscall_arg4(regs))) {
        return;
    }
    const u32 fd = syscall_arg1(regs);
    const struct file *const file = tracing ? current_file_tracing(fd) : current_file_kprobe(fd);
    if (!file) {
        return;
    }
    fs_probe_entry_generic(file, fs_op_sync_file_range, tracing);
}

// fs_probe_entry_sync starts measuring sync(2): the only sync call with no
// file, so no superblock to classify or filter and no root inode to
// attribute to a volume (s_dev=0, root_ino=0, fs_type_unknown so
// system.filesystem.type is omitted; pid_decorator.go skips resolveMount for
// the resulting dev 0, 2.4). sync(2) always attaches by kprobe (el9 has no
// BTF for its wrapper, 2.4), so it always keeps its start in fs_start, never
// in task storage.
static __always_inline void fs_probe_entry_sync(void) {
    const u64 now = bpf_ktime_get_ns();
    const u64 id = bpf_get_current_pid_tgid();
    if (fs_start_nest(bpf_map_lookup_elem(&fs_start, &id), now)) {
        return;
    }
    struct fs_start_val val = {};
    val.ts = now;
    val.fs = fs_type_unknown;
    val.op = fs_op_sync;
    if (bpf_map_update_elem(&fs_start, &id, &val, BPF_ANY)) {
        fs_count_drop(fs_drop_start);
    }
}

// Attach targets are assigned at load time from Go; these placeholder names are
// never resolved by libbpf itself.
SEC("fentry/obi_dummy_fs_read")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fentry_nfs_read, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry_tracing(iocb, fs_type_nfs, fs_op_read);
    return 0;
}

SEC("fexit/obi_dummy_fs_read")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fexit_nfs_read, struct kiocb *iocb, struct iov_iter *to, long ret) {
    (void)ctx;
    (void)iocb;
    (void)to;
    fs_probe_exit_tracing(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_write")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fentry_nfs_write, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry_tracing(iocb, fs_type_nfs, fs_op_write);
    return 0;
}

SEC("fexit/obi_dummy_fs_write")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fexit_nfs_write, struct kiocb *iocb, struct iov_iter *from, long ret) {
    (void)ctx;
    (void)iocb;
    (void)from;
    fs_probe_exit_tracing(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_fsync")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(
    obi_stats_fentry_nfs_fsync, struct file *file, loff_t start, loff_t end, int datasync) {
    (void)ctx;
    (void)start;
    (void)end;
    fs_probe_entry_file_tracing(file, fs_type_nfs, datasync ? fs_op_fdatasync : fs_op_fsync);
    return 0;
}

SEC("fexit/obi_dummy_fs_fsync")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(
    obi_stats_fexit_nfs_fsync, struct file *file, loff_t start, loff_t end, int datasync, int ret) {
    (void)ctx;
    (void)file;
    (void)start;
    (void)end;
    (void)datasync;
    fs_probe_exit_tracing(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_read")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fentry_ceph_read, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry_tracing(iocb, fs_type_ceph, fs_op_read);
    return 0;
}

SEC("fexit/obi_dummy_fs_read")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fexit_ceph_read, struct kiocb *iocb, struct iov_iter *to, long ret) {
    (void)ctx;
    (void)iocb;
    (void)to;
    fs_probe_exit_tracing(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_write")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fentry_ceph_write, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry_tracing(iocb, fs_type_ceph, fs_op_write);
    return 0;
}

SEC("fexit/obi_dummy_fs_write")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fexit_ceph_write, struct kiocb *iocb, struct iov_iter *from, long ret) {
    (void)ctx;
    (void)iocb;
    (void)from;
    fs_probe_exit_tracing(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_fsync")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(
    obi_stats_fentry_ceph_fsync, struct file *file, loff_t start, loff_t end, int datasync) {
    (void)ctx;
    (void)start;
    (void)end;
    fs_probe_entry_file_tracing(file, fs_type_ceph, datasync ? fs_op_fdatasync : fs_op_fsync);
    return 0;
}

SEC("fexit/obi_dummy_fs_fsync")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fexit_ceph_fsync,
             struct file *file,
             loff_t start,
             loff_t end,
             int datasync,
             int ret) {
    (void)ctx;
    (void)file;
    (void)start;
    (void)end;
    (void)datasync;
    fs_probe_exit_tracing(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_read")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fentry_cifs_read, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry_tracing(iocb, fs_type_cifs, fs_op_read);
    return 0;
}

SEC("fexit/obi_dummy_fs_read")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fexit_cifs_read, struct kiocb *iocb, struct iov_iter *to, long ret) {
    (void)ctx;
    (void)iocb;
    (void)to;
    fs_probe_exit_tracing(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_write")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fentry_cifs_write, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry_tracing(iocb, fs_type_cifs, fs_op_write);
    return 0;
}

SEC("fexit/obi_dummy_fs_write")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fexit_cifs_write, struct kiocb *iocb, struct iov_iter *from, long ret) {
    (void)ctx;
    (void)iocb;
    (void)from;
    fs_probe_exit_tracing(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_fsync")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(
    obi_stats_fentry_cifs_fsync, struct file *file, loff_t start, loff_t end, int datasync) {
    (void)ctx;
    (void)start;
    (void)end;
    fs_probe_entry_file_tracing(file, fs_type_cifs, datasync ? fs_op_fdatasync : fs_op_fsync);
    return 0;
}

SEC("fexit/obi_dummy_fs_fsync")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fexit_cifs_fsync,
             struct file *file,
             loff_t start,
             loff_t end,
             int datasync,
             int ret) {
    (void)ctx;
    (void)file;
    (void)start;
    (void)end;
    (void)datasync;
    fs_probe_exit_tracing(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_read")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fentry_fuse_read, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry_tracing(iocb, fs_type_fuse, fs_op_read);
    return 0;
}

SEC("fexit/obi_dummy_fs_read")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fexit_fuse_read, struct kiocb *iocb, struct iov_iter *to, long ret) {
    (void)ctx;
    (void)iocb;
    (void)to;
    fs_probe_exit_tracing(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_write")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fentry_fuse_write, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry_tracing(iocb, fs_type_fuse, fs_op_write);
    return 0;
}

SEC("fexit/obi_dummy_fs_write")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fexit_fuse_write, struct kiocb *iocb, struct iov_iter *from, long ret) {
    (void)ctx;
    (void)iocb;
    (void)from;
    fs_probe_exit_tracing(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_fsync")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(
    obi_stats_fentry_fuse_fsync, struct file *file, loff_t start, loff_t end, int datasync) {
    (void)ctx;
    (void)start;
    (void)end;
    fs_probe_entry_file_tracing(file, fs_type_fuse, datasync ? fs_op_fdatasync : fs_op_fsync);
    return 0;
}

SEC("fexit/obi_dummy_fs_fsync")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fexit_fuse_fsync,
             struct file *file,
             loff_t start,
             loff_t end,
             int datasync,
             int ret) {
    (void)ctx;
    (void)file;
    (void)start;
    (void)end;
    (void)datasync;
    fs_probe_exit_tracing(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_read")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fentry_ext4_read, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry_tracing(iocb, fs_type_ext4, fs_op_read);
    return 0;
}

SEC("fexit/obi_dummy_fs_read")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fexit_ext4_read, struct kiocb *iocb, struct iov_iter *to, long ret) {
    (void)ctx;
    (void)iocb;
    (void)to;
    fs_probe_exit_tracing(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_write")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fentry_ext4_write, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry_tracing(iocb, fs_type_ext4, fs_op_write);
    return 0;
}

SEC("fexit/obi_dummy_fs_write")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fexit_ext4_write, struct kiocb *iocb, struct iov_iter *from, long ret) {
    (void)ctx;
    (void)iocb;
    (void)from;
    fs_probe_exit_tracing(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_fsync")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(
    obi_stats_fentry_ext4_fsync, struct file *file, loff_t start, loff_t end, int datasync) {
    (void)ctx;
    (void)start;
    (void)end;
    fs_probe_entry_file_tracing(file, fs_type_ext4, datasync ? fs_op_fdatasync : fs_op_fsync);
    return 0;
}

SEC("fexit/obi_dummy_fs_fsync")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fexit_ext4_fsync,
             struct file *file,
             loff_t start,
             loff_t end,
             int datasync,
             int ret) {
    (void)ctx;
    (void)file;
    (void)start;
    (void)end;
    (void)datasync;
    fs_probe_exit_tracing(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_read")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fentry_xfs_read, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry_tracing(iocb, fs_type_xfs, fs_op_read);
    return 0;
}

SEC("fexit/obi_dummy_fs_read")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fexit_xfs_read, struct kiocb *iocb, struct iov_iter *to, long ret) {
    (void)ctx;
    (void)iocb;
    (void)to;
    fs_probe_exit_tracing(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_write")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fentry_xfs_write, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry_tracing(iocb, fs_type_xfs, fs_op_write);
    return 0;
}

SEC("fexit/obi_dummy_fs_write")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fexit_xfs_write, struct kiocb *iocb, struct iov_iter *from, long ret) {
    (void)ctx;
    (void)iocb;
    (void)from;
    fs_probe_exit_tracing(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_fsync")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(
    obi_stats_fentry_xfs_fsync, struct file *file, loff_t start, loff_t end, int datasync) {
    (void)ctx;
    (void)start;
    (void)end;
    fs_probe_entry_file_tracing(file, fs_type_xfs, datasync ? fs_op_fdatasync : fs_op_fsync);
    return 0;
}

SEC("fexit/obi_dummy_fs_fsync")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(
    obi_stats_fexit_xfs_fsync, struct file *file, loff_t start, loff_t end, int datasync, int ret) {
    (void)ctx;
    (void)file;
    (void)start;
    (void)end;
    (void)datasync;
    fs_probe_exit_tracing(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_read")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fentry_btrfs_read, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry_tracing(iocb, fs_type_btrfs, fs_op_read);
    return 0;
}

SEC("fexit/obi_dummy_fs_read")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fexit_btrfs_read, struct kiocb *iocb, struct iov_iter *to, long ret) {
    (void)ctx;
    (void)iocb;
    (void)to;
    fs_probe_exit_tracing(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_write")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fentry_btrfs_write, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry_tracing(iocb, fs_type_btrfs, fs_op_write);
    return 0;
}

SEC("fexit/obi_dummy_fs_write")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fexit_btrfs_write, struct kiocb *iocb, struct iov_iter *from, long ret) {
    (void)ctx;
    (void)iocb;
    (void)from;
    fs_probe_exit_tracing(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_fsync")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(
    obi_stats_fentry_btrfs_fsync, struct file *file, loff_t start, loff_t end, int datasync) {
    (void)ctx;
    (void)start;
    (void)end;
    fs_probe_entry_file_tracing(file, fs_type_btrfs, datasync ? fs_op_fdatasync : fs_op_fsync);
    return 0;
}

SEC("fexit/obi_dummy_fs_fsync")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fexit_btrfs_fsync,
             struct file *file,
             loff_t start,
             loff_t end,
             int datasync,
             int ret) {
    (void)ctx;
    (void)file;
    (void)start;
    (void)end;
    (void)datasync;
    fs_probe_exit_tracing(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_read")
int BPF_KPROBE(obi_stats_kprobe_nfs_read, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry_kprobe(iocb, fs_type_nfs, fs_op_read);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_read")
int BPF_KRETPROBE(obi_stats_kretprobe_nfs_read, long ret) {
    (void)ctx;
    fs_probe_exit_kprobe(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_write")
int BPF_KPROBE(obi_stats_kprobe_nfs_write, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry_kprobe(iocb, fs_type_nfs, fs_op_write);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_write")
int BPF_KRETPROBE(obi_stats_kretprobe_nfs_write, long ret) {
    (void)ctx;
    fs_probe_exit_kprobe(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_fsync")
int BPF_KPROBE(
    obi_stats_kprobe_nfs_fsync, struct file *file, loff_t start, loff_t end, int datasync) {
    (void)ctx;
    (void)start;
    (void)end;
    fs_probe_entry_file_kprobe(file, fs_type_nfs, datasync ? fs_op_fdatasync : fs_op_fsync);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_fsync")
int BPF_KRETPROBE(obi_stats_kretprobe_nfs_fsync, long ret) {
    (void)ctx;
    fs_probe_exit_kprobe(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_read")
int BPF_KPROBE(obi_stats_kprobe_ceph_read, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry_kprobe(iocb, fs_type_ceph, fs_op_read);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_read")
int BPF_KRETPROBE(obi_stats_kretprobe_ceph_read, long ret) {
    (void)ctx;
    fs_probe_exit_kprobe(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_write")
int BPF_KPROBE(obi_stats_kprobe_ceph_write, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry_kprobe(iocb, fs_type_ceph, fs_op_write);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_write")
int BPF_KRETPROBE(obi_stats_kretprobe_ceph_write, long ret) {
    (void)ctx;
    fs_probe_exit_kprobe(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_fsync")
int BPF_KPROBE(
    obi_stats_kprobe_ceph_fsync, struct file *file, loff_t start, loff_t end, int datasync) {
    (void)ctx;
    (void)start;
    (void)end;
    fs_probe_entry_file_kprobe(file, fs_type_ceph, datasync ? fs_op_fdatasync : fs_op_fsync);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_fsync")
int BPF_KRETPROBE(obi_stats_kretprobe_ceph_fsync, long ret) {
    (void)ctx;
    fs_probe_exit_kprobe(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_read")
int BPF_KPROBE(obi_stats_kprobe_cifs_read, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry_kprobe(iocb, fs_type_cifs, fs_op_read);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_read")
int BPF_KRETPROBE(obi_stats_kretprobe_cifs_read, long ret) {
    (void)ctx;
    fs_probe_exit_kprobe(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_write")
int BPF_KPROBE(obi_stats_kprobe_cifs_write, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry_kprobe(iocb, fs_type_cifs, fs_op_write);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_write")
int BPF_KRETPROBE(obi_stats_kretprobe_cifs_write, long ret) {
    (void)ctx;
    fs_probe_exit_kprobe(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_fsync")
int BPF_KPROBE(
    obi_stats_kprobe_cifs_fsync, struct file *file, loff_t start, loff_t end, int datasync) {
    (void)ctx;
    (void)start;
    (void)end;
    fs_probe_entry_file_kprobe(file, fs_type_cifs, datasync ? fs_op_fdatasync : fs_op_fsync);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_fsync")
int BPF_KRETPROBE(obi_stats_kretprobe_cifs_fsync, long ret) {
    (void)ctx;
    fs_probe_exit_kprobe(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_read")
int BPF_KPROBE(obi_stats_kprobe_fuse_read, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry_kprobe(iocb, fs_type_fuse, fs_op_read);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_read")
int BPF_KRETPROBE(obi_stats_kretprobe_fuse_read, long ret) {
    (void)ctx;
    fs_probe_exit_kprobe(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_write")
int BPF_KPROBE(obi_stats_kprobe_fuse_write, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry_kprobe(iocb, fs_type_fuse, fs_op_write);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_write")
int BPF_KRETPROBE(obi_stats_kretprobe_fuse_write, long ret) {
    (void)ctx;
    fs_probe_exit_kprobe(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_fsync")
int BPF_KPROBE(
    obi_stats_kprobe_fuse_fsync, struct file *file, loff_t start, loff_t end, int datasync) {
    (void)ctx;
    (void)start;
    (void)end;
    fs_probe_entry_file_kprobe(file, fs_type_fuse, datasync ? fs_op_fdatasync : fs_op_fsync);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_fsync")
int BPF_KRETPROBE(obi_stats_kretprobe_fuse_fsync, long ret) {
    (void)ctx;
    fs_probe_exit_kprobe(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_read")
int BPF_KPROBE(obi_stats_kprobe_ext4_read, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry_kprobe(iocb, fs_type_ext4, fs_op_read);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_read")
int BPF_KRETPROBE(obi_stats_kretprobe_ext4_read, long ret) {
    (void)ctx;
    fs_probe_exit_kprobe(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_write")
int BPF_KPROBE(obi_stats_kprobe_ext4_write, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry_kprobe(iocb, fs_type_ext4, fs_op_write);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_write")
int BPF_KRETPROBE(obi_stats_kretprobe_ext4_write, long ret) {
    (void)ctx;
    fs_probe_exit_kprobe(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_fsync")
int BPF_KPROBE(
    obi_stats_kprobe_ext4_fsync, struct file *file, loff_t start, loff_t end, int datasync) {
    (void)ctx;
    (void)start;
    (void)end;
    fs_probe_entry_file_kprobe(file, fs_type_ext4, datasync ? fs_op_fdatasync : fs_op_fsync);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_fsync")
int BPF_KRETPROBE(obi_stats_kretprobe_ext4_fsync, long ret) {
    (void)ctx;
    fs_probe_exit_kprobe(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_read")
int BPF_KPROBE(obi_stats_kprobe_xfs_read, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry_kprobe(iocb, fs_type_xfs, fs_op_read);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_read")
int BPF_KRETPROBE(obi_stats_kretprobe_xfs_read, long ret) {
    (void)ctx;
    fs_probe_exit_kprobe(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_write")
int BPF_KPROBE(obi_stats_kprobe_xfs_write, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry_kprobe(iocb, fs_type_xfs, fs_op_write);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_write")
int BPF_KRETPROBE(obi_stats_kretprobe_xfs_write, long ret) {
    (void)ctx;
    fs_probe_exit_kprobe(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_fsync")
int BPF_KPROBE(
    obi_stats_kprobe_xfs_fsync, struct file *file, loff_t start, loff_t end, int datasync) {
    (void)ctx;
    (void)start;
    (void)end;
    fs_probe_entry_file_kprobe(file, fs_type_xfs, datasync ? fs_op_fdatasync : fs_op_fsync);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_fsync")
int BPF_KRETPROBE(obi_stats_kretprobe_xfs_fsync, long ret) {
    (void)ctx;
    fs_probe_exit_kprobe(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_read")
int BPF_KPROBE(obi_stats_kprobe_btrfs_read, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry_kprobe(iocb, fs_type_btrfs, fs_op_read);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_read")
int BPF_KRETPROBE(obi_stats_kretprobe_btrfs_read, long ret) {
    (void)ctx;
    fs_probe_exit_kprobe(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_write")
int BPF_KPROBE(obi_stats_kprobe_btrfs_write, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry_kprobe(iocb, fs_type_btrfs, fs_op_write);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_write")
int BPF_KRETPROBE(obi_stats_kretprobe_btrfs_write, long ret) {
    (void)ctx;
    fs_probe_exit_kprobe(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_fsync")
int BPF_KPROBE(
    obi_stats_kprobe_btrfs_fsync, struct file *file, loff_t start, loff_t end, int datasync) {
    (void)ctx;
    (void)start;
    (void)end;
    fs_probe_entry_file_kprobe(file, fs_type_btrfs, datasync ? fs_op_fdatasync : fs_op_fsync);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_fsync")
int BPF_KRETPROBE(obi_stats_kretprobe_btrfs_fsync, long ret) {
    (void)ctx;
    fs_probe_exit_kprobe(ret);
    return 0;
}

// splice(2), sendfile(2) and copy_file_range(2) do not go through read_iter:
// they call the filesystem's splice_read operation instead, so a file server
// built on sendfile would otherwise report no filesystem I/O at all. Only the
// filesystems with their own symbol are probed; ceph, cifs and xfs use the
// generic filemap_splice_read, which every filesystem on the node shares.
// These are recorded as reads, which is what they are to the application.

SEC("fentry/obi_dummy_fs_splice_read")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fentry_nfs_splice_read, struct file *in) {
    (void)ctx;
    fs_probe_entry_file_tracing(in, fs_type_nfs, fs_op_read);
    return 0;
}

SEC("fexit/obi_dummy_fs_splice_read")
// NOLINTBEGIN(readability-non-const-parameter)
int BPF_PROG(obi_stats_fexit_nfs_splice_read,
             struct file *in,
             loff_t *ppos,
             struct pipe_inode_info *pipe,
             size_t len,
             unsigned int flags,
             long ret) {
    // NOLINTEND(readability-non-const-parameter)
    (void)ctx;
    (void)in;
    (void)ppos;
    (void)pipe;
    (void)len;
    (void)flags;
    fs_probe_exit_tracing(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_splice_read")
int BPF_KPROBE(obi_stats_kprobe_nfs_splice_read, struct file *in) {
    (void)ctx;
    fs_probe_entry_file_kprobe(in, fs_type_nfs, fs_op_read);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_splice_read")
int BPF_KRETPROBE(obi_stats_kretprobe_nfs_splice_read, long ret) {
    (void)ctx;
    fs_probe_exit_kprobe(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_splice_read")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fentry_fuse_splice_read, struct file *in) {
    (void)ctx;
    fs_probe_entry_file_tracing(in, fs_type_fuse, fs_op_read);
    return 0;
}

SEC("fexit/obi_dummy_fs_splice_read")
// NOLINTBEGIN(readability-non-const-parameter)
int BPF_PROG(obi_stats_fexit_fuse_splice_read,
             struct file *in,
             loff_t *ppos,
             struct pipe_inode_info *pipe,
             size_t len,
             unsigned int flags,
             long ret) {
    // NOLINTEND(readability-non-const-parameter)
    (void)ctx;
    (void)in;
    (void)ppos;
    (void)pipe;
    (void)len;
    (void)flags;
    fs_probe_exit_tracing(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_splice_read")
int BPF_KPROBE(obi_stats_kprobe_fuse_splice_read, struct file *in) {
    (void)ctx;
    fs_probe_entry_file_kprobe(in, fs_type_fuse, fs_op_read);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_splice_read")
int BPF_KRETPROBE(obi_stats_kretprobe_fuse_splice_read, long ret) {
    (void)ctx;
    fs_probe_exit_kprobe(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_splice_read")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fentry_ext4_splice_read, struct file *in) {
    (void)ctx;
    fs_probe_entry_file_tracing(in, fs_type_ext4, fs_op_read);
    return 0;
}

SEC("fexit/obi_dummy_fs_splice_read")
// NOLINTBEGIN(readability-non-const-parameter)
int BPF_PROG(obi_stats_fexit_ext4_splice_read,
             struct file *in,
             loff_t *ppos,
             struct pipe_inode_info *pipe,
             size_t len,
             unsigned int flags,
             long ret) {
    // NOLINTEND(readability-non-const-parameter)
    (void)ctx;
    (void)in;
    (void)ppos;
    (void)pipe;
    (void)len;
    (void)flags;
    fs_probe_exit_tracing(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_splice_read")
int BPF_KPROBE(obi_stats_kprobe_ext4_splice_read, struct file *in) {
    (void)ctx;
    fs_probe_entry_file_kprobe(in, fs_type_ext4, fs_op_read);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_splice_read")
int BPF_KRETPROBE(obi_stats_kretprobe_ext4_splice_read, long ret) {
    (void)ctx;
    fs_probe_exit_kprobe(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_splice_read")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fentry_btrfs_splice_read, struct file *in) {
    (void)ctx;
    fs_probe_entry_file_tracing(in, fs_type_btrfs, fs_op_read);
    return 0;
}

SEC("fexit/obi_dummy_fs_splice_read")
// NOLINTBEGIN(readability-non-const-parameter)
int BPF_PROG(obi_stats_fexit_btrfs_splice_read,
             struct file *in,
             loff_t *ppos,
             struct pipe_inode_info *pipe,
             size_t len,
             unsigned int flags,
             long ret) {
    // NOLINTEND(readability-non-const-parameter)
    (void)ctx;
    (void)in;
    (void)ppos;
    (void)pipe;
    (void)len;
    (void)flags;
    fs_probe_exit_tracing(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_splice_read")
int BPF_KPROBE(obi_stats_kprobe_btrfs_splice_read, struct file *in) {
    (void)ctx;
    fs_probe_entry_file_kprobe(in, fs_type_btrfs, fs_op_read);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_splice_read")
int BPF_KRETPROBE(obi_stats_kretprobe_btrfs_splice_read, long ret) {
    (void)ctx;
    fs_probe_exit_kprobe(ret);
    return 0;
}

// Step 14: sync, syncfs, sync_file_range (storage_fs_sync). These attach to
// the syscall wrappers rather than to a filesystem's own file_operations,
// since only the wrapper is guaranteed not to be inlined on every build
// (2.4); the attach target (a GOARCH-specific symbol name) is assigned at
// load time from Go, like the per-filesystem dummy names above.

SEC("fentry/obi_dummy_syscall_syncfs")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fentry_syncfs, const struct pt_regs *regs) {
    (void)ctx;
    fs_probe_entry_syncfs(regs, true);
    return 0;
}

SEC("fexit/obi_dummy_syscall_syncfs")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fexit_syncfs, const struct pt_regs *regs, long ret) {
    (void)ctx;
    (void)regs;
    fs_probe_exit_tracing(ret);
    return 0;
}

SEC("kprobe/obi_dummy_syscall_syncfs")
int BPF_KPROBE(obi_stats_kprobe_syncfs, struct pt_regs *regs) {
    (void)ctx;
    fs_probe_entry_syncfs(regs, false);
    return 0;
}

SEC("kretprobe/obi_dummy_syscall_syncfs")
int BPF_KRETPROBE(obi_stats_kretprobe_syncfs, long ret) {
    (void)ctx;
    fs_probe_exit_kprobe(ret);
    return 0;
}

SEC("fentry/obi_dummy_syscall_sync_file_range")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fentry_sync_file_range, const struct pt_regs *regs) {
    (void)ctx;
    fs_probe_entry_sync_file_range(regs, true);
    return 0;
}

SEC("fexit/obi_dummy_syscall_sync_file_range")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fexit_sync_file_range, const struct pt_regs *regs, long ret) {
    (void)ctx;
    (void)regs;
    fs_probe_exit_tracing(ret);
    return 0;
}

SEC("kprobe/obi_dummy_syscall_sync_file_range")
int BPF_KPROBE(obi_stats_kprobe_sync_file_range, struct pt_regs *regs) {
    (void)ctx;
    fs_probe_entry_sync_file_range(regs, false);
    return 0;
}

SEC("kretprobe/obi_dummy_syscall_sync_file_range")
int BPF_KRETPROBE(obi_stats_kretprobe_sync_file_range, long ret) {
    (void)ctx;
    fs_probe_exit_kprobe(ret);
    return 0;
}

// sync(2) has no fentry/fexit variant: el9 has no BTF for its wrapper, so
// fentry is impossible there, and sync(2) is rare enough that the kprobe
// cost never matters (2.4).
SEC("kprobe/obi_dummy_syscall_sync")
int BPF_KPROBE(obi_stats_kprobe_sync) {
    (void)ctx;
    fs_probe_entry_sync();
    return 0;
}

SEC("kretprobe/obi_dummy_syscall_sync")
int BPF_KRETPROBE(obi_stats_kretprobe_sync, long ret) {
    (void)ctx;
    fs_probe_exit_kprobe(ret);
    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
