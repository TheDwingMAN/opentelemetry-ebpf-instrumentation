// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_core_read.h>
#include <bpfcore/bpf_tracing.h>

#include <logger/bpf_dbg.h>
#include <pid/pid_helpers.h>

#include <statsolly/types.h>
#include <statsolly/maps/stats_events.h>
#include <statsolly/maps/fs_start.h>
#include <statsolly/maps/fs_dev_filter.h>

// Kernel-internal completion marker (include/linux/errno.h), not a real
// failure: an async iocb was queued and will complete later on its own,
// without OBI observing that completion.
enum { k_eiocbqueued = 529 };

static __always_inline void
fs_probe_entry_file(const struct file *const file, const enum fs_type fs, const enum fs_op op) {
    const u32 s_dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev);

    // ext4/xfs/btrfs also back the node's own root filesystem and every
    // container's writable layer, so only record when the device is a known
    // PV-backed mount (fs_dev_filter, populated from userspace). Network
    // filesystems are never used for the node's own root, so they stay
    // unfiltered.
    const bool is_local_fs = fs == fs_type_ext4 || fs == fs_type_xfs || fs == fs_type_btrfs;
    if (is_local_fs && !bpf_map_lookup_elem(&fs_dev_filter, &s_dev)) {
        return;
    }

    const u64 id = bpf_get_current_pid_tgid();

    // O_SYNC/O_DSYNC writes call the filesystem's fsync file_operation on the
    // same thread as the write (ext4_file_write_iter -> generic_write_sync ->
    // ext4_sync_file; same for xfs, nfs, ceph, fuse). Without this check, the
    // nested fsync's entry would overwrite the outer write's fs_start entry
    // and its exit would delete it, so the write would emit nothing. Track
    // nesting depth instead and let only the outermost exit emit.
    struct fs_start_val *const existing = bpf_map_lookup_elem(&fs_start, &id);
    if (existing) {
        existing->depth++;
        return;
    }

    struct fs_start_val val = {};

    val.ts = bpf_ktime_get_ns();
    val.s_dev = s_dev;
    val.fs = fs;
    val.op = op;
    val.depth = 0;

    pid_info pid = {};
    task_pid(&pid);
    val.host_pid = pid.host_pid;
    val.pid_ns = pid.ns;

    bpf_map_update_elem(&fs_start, &id, &val, BPF_ANY);
}

static __always_inline void
fs_probe_entry(const struct kiocb *const iocb, const enum fs_type fs, const enum fs_op op) {
    const struct file *const file = BPF_CORE_READ(iocb, ki_filp);
    fs_probe_entry_file(file, fs, op);
}

static __always_inline void fs_probe_exit(const long ret) {
    const u64 id = bpf_get_current_pid_tgid();
    struct fs_start_val *const start = bpf_map_lookup_elem(&fs_start, &id);
    if (!start) {
        return;
    }

    // This exit belongs to a nested operation (see fs_probe_entry_file);
    // only the outermost exit reads and emits the entry.
    if (start->depth > 0) {
        start->depth--;
        return;
    }

    const u64 latency = bpf_ktime_get_ns() - start->ts;
    const u32 s_dev = start->s_dev;
    const u32 host_pid = start->host_pid;
    const u32 pid_ns = start->pid_ns;
    const u8 fs = start->fs;
    const u8 op = start->op;
    bpf_map_delete_elem(&fs_start, &id);

    // read/write treat ret == 0 as EOF and -EIOCBQUEUED as a deferred async
    // completion, neither worth an event; fsync returns 0 on success, so it
    // must still fall through to record that completion.
    const bool is_sync_op = op == fs_op_fsync || op == fs_op_fdatasync;
    if (!is_sync_op && (ret == 0 || ret == -k_eiocbqueued)) {
        return;
    }

    fs_io_t *const se = bpf_ringbuf_reserve(&stats_events, sizeof(*se), 0);
    if (!se) {
        bpf_d_printk("fs_io: stats_events ring buffer full, dropping event");
        return;
    }

    se->flags = k_stat_type_fs_io;
    se->fs = fs;
    se->op = op;
    se->_pad[0] = 0;
    se->s_dev = s_dev;
    se->host_pid = host_pid;
    se->pid_ns = pid_ns;
    se->latency_ns = latency;
    se->bytes = ret > 0 ? (u64)ret : 0;
    se->error = ret < 0 ? (s32)ret : 0;
    se->_pad2[0] = 0;
    se->_pad2[1] = 0;
    se->_pad2[2] = 0;
    se->_pad2[3] = 0;

    bpf_ringbuf_submit(se, stats_events_flags());
}

// Attach targets are assigned at load time from Go; these placeholder names are
// never resolved by libbpf itself.
SEC("fentry/obi_dummy_fs_read")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fentry_nfs_read, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry(iocb, fs_type_nfs, fs_op_read);
    return 0;
}

SEC("fexit/obi_dummy_fs_read")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fexit_nfs_read, struct kiocb *iocb, struct iov_iter *to, long ret) {
    (void)ctx;
    (void)iocb;
    (void)to;
    fs_probe_exit(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_write")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fentry_nfs_write, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry(iocb, fs_type_nfs, fs_op_write);
    return 0;
}

SEC("fexit/obi_dummy_fs_write")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fexit_nfs_write, struct kiocb *iocb, struct iov_iter *from, long ret) {
    (void)ctx;
    (void)iocb;
    (void)from;
    fs_probe_exit(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_fsync")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(
    obi_stats_fentry_nfs_fsync, struct file *file, loff_t start, loff_t end, int datasync) {
    (void)ctx;
    (void)start;
    (void)end;
    fs_probe_entry_file(file, fs_type_nfs, datasync ? fs_op_fdatasync : fs_op_fsync);
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
    fs_probe_exit(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_read")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fentry_ceph_read, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry(iocb, fs_type_ceph, fs_op_read);
    return 0;
}

SEC("fexit/obi_dummy_fs_read")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fexit_ceph_read, struct kiocb *iocb, struct iov_iter *to, long ret) {
    (void)ctx;
    (void)iocb;
    (void)to;
    fs_probe_exit(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_write")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fentry_ceph_write, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry(iocb, fs_type_ceph, fs_op_write);
    return 0;
}

SEC("fexit/obi_dummy_fs_write")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fexit_ceph_write, struct kiocb *iocb, struct iov_iter *from, long ret) {
    (void)ctx;
    (void)iocb;
    (void)from;
    fs_probe_exit(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_fsync")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(
    obi_stats_fentry_ceph_fsync, struct file *file, loff_t start, loff_t end, int datasync) {
    (void)ctx;
    (void)start;
    (void)end;
    fs_probe_entry_file(file, fs_type_ceph, datasync ? fs_op_fdatasync : fs_op_fsync);
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
    fs_probe_exit(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_read")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fentry_cifs_read, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry(iocb, fs_type_cifs, fs_op_read);
    return 0;
}

SEC("fexit/obi_dummy_fs_read")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fexit_cifs_read, struct kiocb *iocb, struct iov_iter *to, long ret) {
    (void)ctx;
    (void)iocb;
    (void)to;
    fs_probe_exit(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_write")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fentry_cifs_write, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry(iocb, fs_type_cifs, fs_op_write);
    return 0;
}

SEC("fexit/obi_dummy_fs_write")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fexit_cifs_write, struct kiocb *iocb, struct iov_iter *from, long ret) {
    (void)ctx;
    (void)iocb;
    (void)from;
    fs_probe_exit(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_fsync")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(
    obi_stats_fentry_cifs_fsync, struct file *file, loff_t start, loff_t end, int datasync) {
    (void)ctx;
    (void)start;
    (void)end;
    fs_probe_entry_file(file, fs_type_cifs, datasync ? fs_op_fdatasync : fs_op_fsync);
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
    fs_probe_exit(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_read")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fentry_fuse_read, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry(iocb, fs_type_fuse, fs_op_read);
    return 0;
}

SEC("fexit/obi_dummy_fs_read")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fexit_fuse_read, struct kiocb *iocb, struct iov_iter *to, long ret) {
    (void)ctx;
    (void)iocb;
    (void)to;
    fs_probe_exit(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_write")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fentry_fuse_write, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry(iocb, fs_type_fuse, fs_op_write);
    return 0;
}

SEC("fexit/obi_dummy_fs_write")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fexit_fuse_write, struct kiocb *iocb, struct iov_iter *from, long ret) {
    (void)ctx;
    (void)iocb;
    (void)from;
    fs_probe_exit(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_fsync")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(
    obi_stats_fentry_fuse_fsync, struct file *file, loff_t start, loff_t end, int datasync) {
    (void)ctx;
    (void)start;
    (void)end;
    fs_probe_entry_file(file, fs_type_fuse, datasync ? fs_op_fdatasync : fs_op_fsync);
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
    fs_probe_exit(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_read")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fentry_ext4_read, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry(iocb, fs_type_ext4, fs_op_read);
    return 0;
}

SEC("fexit/obi_dummy_fs_read")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fexit_ext4_read, struct kiocb *iocb, struct iov_iter *to, long ret) {
    (void)ctx;
    (void)iocb;
    (void)to;
    fs_probe_exit(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_write")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fentry_ext4_write, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry(iocb, fs_type_ext4, fs_op_write);
    return 0;
}

SEC("fexit/obi_dummy_fs_write")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fexit_ext4_write, struct kiocb *iocb, struct iov_iter *from, long ret) {
    (void)ctx;
    (void)iocb;
    (void)from;
    fs_probe_exit(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_fsync")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(
    obi_stats_fentry_ext4_fsync, struct file *file, loff_t start, loff_t end, int datasync) {
    (void)ctx;
    (void)start;
    (void)end;
    fs_probe_entry_file(file, fs_type_ext4, datasync ? fs_op_fdatasync : fs_op_fsync);
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
    fs_probe_exit(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_read")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fentry_xfs_read, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry(iocb, fs_type_xfs, fs_op_read);
    return 0;
}

SEC("fexit/obi_dummy_fs_read")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fexit_xfs_read, struct kiocb *iocb, struct iov_iter *to, long ret) {
    (void)ctx;
    (void)iocb;
    (void)to;
    fs_probe_exit(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_write")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fentry_xfs_write, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry(iocb, fs_type_xfs, fs_op_write);
    return 0;
}

SEC("fexit/obi_dummy_fs_write")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fexit_xfs_write, struct kiocb *iocb, struct iov_iter *from, long ret) {
    (void)ctx;
    (void)iocb;
    (void)from;
    fs_probe_exit(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_fsync")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(
    obi_stats_fentry_xfs_fsync, struct file *file, loff_t start, loff_t end, int datasync) {
    (void)ctx;
    (void)start;
    (void)end;
    fs_probe_entry_file(file, fs_type_xfs, datasync ? fs_op_fdatasync : fs_op_fsync);
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
    fs_probe_exit(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_read")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fentry_btrfs_read, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry(iocb, fs_type_btrfs, fs_op_read);
    return 0;
}

SEC("fexit/obi_dummy_fs_read")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fexit_btrfs_read, struct kiocb *iocb, struct iov_iter *to, long ret) {
    (void)ctx;
    (void)iocb;
    (void)to;
    fs_probe_exit(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_write")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fentry_btrfs_write, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry(iocb, fs_type_btrfs, fs_op_write);
    return 0;
}

SEC("fexit/obi_dummy_fs_write")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fexit_btrfs_write, struct kiocb *iocb, struct iov_iter *from, long ret) {
    (void)ctx;
    (void)iocb;
    (void)from;
    fs_probe_exit(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_fsync")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(
    obi_stats_fentry_btrfs_fsync, struct file *file, loff_t start, loff_t end, int datasync) {
    (void)ctx;
    (void)start;
    (void)end;
    fs_probe_entry_file(file, fs_type_btrfs, datasync ? fs_op_fdatasync : fs_op_fsync);
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
    fs_probe_exit(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_read")
int BPF_KPROBE(obi_stats_kprobe_nfs_read, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry(iocb, fs_type_nfs, fs_op_read);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_read")
int BPF_KRETPROBE(obi_stats_kretprobe_nfs_read, long ret) {
    (void)ctx;
    fs_probe_exit(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_write")
int BPF_KPROBE(obi_stats_kprobe_nfs_write, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry(iocb, fs_type_nfs, fs_op_write);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_write")
int BPF_KRETPROBE(obi_stats_kretprobe_nfs_write, long ret) {
    (void)ctx;
    fs_probe_exit(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_fsync")
int BPF_KPROBE(
    obi_stats_kprobe_nfs_fsync, struct file *file, loff_t start, loff_t end, int datasync) {
    (void)ctx;
    (void)start;
    (void)end;
    fs_probe_entry_file(file, fs_type_nfs, datasync ? fs_op_fdatasync : fs_op_fsync);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_fsync")
int BPF_KRETPROBE(obi_stats_kretprobe_nfs_fsync, long ret) {
    (void)ctx;
    fs_probe_exit(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_read")
int BPF_KPROBE(obi_stats_kprobe_ceph_read, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry(iocb, fs_type_ceph, fs_op_read);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_read")
int BPF_KRETPROBE(obi_stats_kretprobe_ceph_read, long ret) {
    (void)ctx;
    fs_probe_exit(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_write")
int BPF_KPROBE(obi_stats_kprobe_ceph_write, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry(iocb, fs_type_ceph, fs_op_write);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_write")
int BPF_KRETPROBE(obi_stats_kretprobe_ceph_write, long ret) {
    (void)ctx;
    fs_probe_exit(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_fsync")
int BPF_KPROBE(
    obi_stats_kprobe_ceph_fsync, struct file *file, loff_t start, loff_t end, int datasync) {
    (void)ctx;
    (void)start;
    (void)end;
    fs_probe_entry_file(file, fs_type_ceph, datasync ? fs_op_fdatasync : fs_op_fsync);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_fsync")
int BPF_KRETPROBE(obi_stats_kretprobe_ceph_fsync, long ret) {
    (void)ctx;
    fs_probe_exit(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_read")
int BPF_KPROBE(obi_stats_kprobe_cifs_read, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry(iocb, fs_type_cifs, fs_op_read);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_read")
int BPF_KRETPROBE(obi_stats_kretprobe_cifs_read, long ret) {
    (void)ctx;
    fs_probe_exit(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_write")
int BPF_KPROBE(obi_stats_kprobe_cifs_write, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry(iocb, fs_type_cifs, fs_op_write);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_write")
int BPF_KRETPROBE(obi_stats_kretprobe_cifs_write, long ret) {
    (void)ctx;
    fs_probe_exit(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_fsync")
int BPF_KPROBE(
    obi_stats_kprobe_cifs_fsync, struct file *file, loff_t start, loff_t end, int datasync) {
    (void)ctx;
    (void)start;
    (void)end;
    fs_probe_entry_file(file, fs_type_cifs, datasync ? fs_op_fdatasync : fs_op_fsync);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_fsync")
int BPF_KRETPROBE(obi_stats_kretprobe_cifs_fsync, long ret) {
    (void)ctx;
    fs_probe_exit(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_read")
int BPF_KPROBE(obi_stats_kprobe_fuse_read, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry(iocb, fs_type_fuse, fs_op_read);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_read")
int BPF_KRETPROBE(obi_stats_kretprobe_fuse_read, long ret) {
    (void)ctx;
    fs_probe_exit(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_write")
int BPF_KPROBE(obi_stats_kprobe_fuse_write, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry(iocb, fs_type_fuse, fs_op_write);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_write")
int BPF_KRETPROBE(obi_stats_kretprobe_fuse_write, long ret) {
    (void)ctx;
    fs_probe_exit(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_fsync")
int BPF_KPROBE(
    obi_stats_kprobe_fuse_fsync, struct file *file, loff_t start, loff_t end, int datasync) {
    (void)ctx;
    (void)start;
    (void)end;
    fs_probe_entry_file(file, fs_type_fuse, datasync ? fs_op_fdatasync : fs_op_fsync);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_fsync")
int BPF_KRETPROBE(obi_stats_kretprobe_fuse_fsync, long ret) {
    (void)ctx;
    fs_probe_exit(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_read")
int BPF_KPROBE(obi_stats_kprobe_ext4_read, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry(iocb, fs_type_ext4, fs_op_read);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_read")
int BPF_KRETPROBE(obi_stats_kretprobe_ext4_read, long ret) {
    (void)ctx;
    fs_probe_exit(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_write")
int BPF_KPROBE(obi_stats_kprobe_ext4_write, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry(iocb, fs_type_ext4, fs_op_write);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_write")
int BPF_KRETPROBE(obi_stats_kretprobe_ext4_write, long ret) {
    (void)ctx;
    fs_probe_exit(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_fsync")
int BPF_KPROBE(
    obi_stats_kprobe_ext4_fsync, struct file *file, loff_t start, loff_t end, int datasync) {
    (void)ctx;
    (void)start;
    (void)end;
    fs_probe_entry_file(file, fs_type_ext4, datasync ? fs_op_fdatasync : fs_op_fsync);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_fsync")
int BPF_KRETPROBE(obi_stats_kretprobe_ext4_fsync, long ret) {
    (void)ctx;
    fs_probe_exit(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_read")
int BPF_KPROBE(obi_stats_kprobe_xfs_read, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry(iocb, fs_type_xfs, fs_op_read);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_read")
int BPF_KRETPROBE(obi_stats_kretprobe_xfs_read, long ret) {
    (void)ctx;
    fs_probe_exit(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_write")
int BPF_KPROBE(obi_stats_kprobe_xfs_write, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry(iocb, fs_type_xfs, fs_op_write);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_write")
int BPF_KRETPROBE(obi_stats_kretprobe_xfs_write, long ret) {
    (void)ctx;
    fs_probe_exit(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_fsync")
int BPF_KPROBE(
    obi_stats_kprobe_xfs_fsync, struct file *file, loff_t start, loff_t end, int datasync) {
    (void)ctx;
    (void)start;
    (void)end;
    fs_probe_entry_file(file, fs_type_xfs, datasync ? fs_op_fdatasync : fs_op_fsync);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_fsync")
int BPF_KRETPROBE(obi_stats_kretprobe_xfs_fsync, long ret) {
    (void)ctx;
    fs_probe_exit(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_read")
int BPF_KPROBE(obi_stats_kprobe_btrfs_read, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry(iocb, fs_type_btrfs, fs_op_read);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_read")
int BPF_KRETPROBE(obi_stats_kretprobe_btrfs_read, long ret) {
    (void)ctx;
    fs_probe_exit(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_write")
int BPF_KPROBE(obi_stats_kprobe_btrfs_write, struct kiocb *iocb) {
    (void)ctx;
    fs_probe_entry(iocb, fs_type_btrfs, fs_op_write);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_write")
int BPF_KRETPROBE(obi_stats_kretprobe_btrfs_write, long ret) {
    (void)ctx;
    fs_probe_exit(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_fsync")
int BPF_KPROBE(
    obi_stats_kprobe_btrfs_fsync, struct file *file, loff_t start, loff_t end, int datasync) {
    (void)ctx;
    (void)start;
    (void)end;
    fs_probe_entry_file(file, fs_type_btrfs, datasync ? fs_op_fdatasync : fs_op_fsync);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_fsync")
int BPF_KRETPROBE(obi_stats_kretprobe_btrfs_fsync, long ret) {
    (void)ctx;
    fs_probe_exit(ret);
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
    fs_probe_entry_file(in, fs_type_nfs, fs_op_read);
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
    fs_probe_exit(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_splice_read")
int BPF_KPROBE(obi_stats_kprobe_nfs_splice_read, struct file *in) {
    (void)ctx;
    fs_probe_entry_file(in, fs_type_nfs, fs_op_read);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_splice_read")
int BPF_KRETPROBE(obi_stats_kretprobe_nfs_splice_read, long ret) {
    (void)ctx;
    fs_probe_exit(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_splice_read")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fentry_fuse_splice_read, struct file *in) {
    (void)ctx;
    fs_probe_entry_file(in, fs_type_fuse, fs_op_read);
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
    fs_probe_exit(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_splice_read")
int BPF_KPROBE(obi_stats_kprobe_fuse_splice_read, struct file *in) {
    (void)ctx;
    fs_probe_entry_file(in, fs_type_fuse, fs_op_read);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_splice_read")
int BPF_KRETPROBE(obi_stats_kretprobe_fuse_splice_read, long ret) {
    (void)ctx;
    fs_probe_exit(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_splice_read")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fentry_ext4_splice_read, struct file *in) {
    (void)ctx;
    fs_probe_entry_file(in, fs_type_ext4, fs_op_read);
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
    fs_probe_exit(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_splice_read")
int BPF_KPROBE(obi_stats_kprobe_ext4_splice_read, struct file *in) {
    (void)ctx;
    fs_probe_entry_file(in, fs_type_ext4, fs_op_read);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_splice_read")
int BPF_KRETPROBE(obi_stats_kretprobe_ext4_splice_read, long ret) {
    (void)ctx;
    fs_probe_exit(ret);
    return 0;
}

SEC("fentry/obi_dummy_fs_splice_read")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_fentry_btrfs_splice_read, struct file *in) {
    (void)ctx;
    fs_probe_entry_file(in, fs_type_btrfs, fs_op_read);
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
    fs_probe_exit(ret);
    return 0;
}

SEC("kprobe/obi_dummy_fs_splice_read")
int BPF_KPROBE(obi_stats_kprobe_btrfs_splice_read, struct file *in) {
    (void)ctx;
    fs_probe_entry_file(in, fs_type_btrfs, fs_op_read);
    return 0;
}

SEC("kretprobe/obi_dummy_fs_splice_read")
int BPF_KRETPROBE(obi_stats_kretprobe_btrfs_splice_read, long ret) {
    (void)ctx;
    fs_probe_exit(ret);
    return 0;
}
