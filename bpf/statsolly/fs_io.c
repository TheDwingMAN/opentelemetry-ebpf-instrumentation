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

// Kernel-internal completion marker (include/linux/errno.h), not a real
// failure: an async iocb was queued and will complete later on its own,
// without OBI observing that completion.
enum { k_eiocbqueued = 529 };

static __always_inline void
fs_probe_entry(const struct kiocb *const iocb, const enum fs_type fs, const enum fs_op op) {
    struct fs_start_val val = {};

    val.ts = bpf_ktime_get_ns();
    val.s_dev = BPF_CORE_READ(iocb, ki_filp, f_inode, i_sb, s_dev);
    val.fs = fs;
    val.op = op;

    pid_info pid = {};
    task_pid(&pid);
    val.host_pid = pid.host_pid;
    val.pid_ns = pid.ns;

    const u64 id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&fs_start, &id, &val, BPF_ANY);
}

static __always_inline void fs_probe_exit(const long ret) {
    const u64 id = bpf_get_current_pid_tgid();
    const struct fs_start_val *const start = bpf_map_lookup_elem(&fs_start, &id);
    if (!start) {
        return;
    }

    const u64 latency = bpf_ktime_get_ns() - start->ts;
    const u32 s_dev = start->s_dev;
    const u32 host_pid = start->host_pid;
    const u32 pid_ns = start->pid_ns;
    const u8 fs = start->fs;
    const u8 op = start->op;
    bpf_map_delete_elem(&fs_start, &id);

    if (ret == 0 || ret == -k_eiocbqueued) {
        return;
    }

    fs_io_t *const se = bpf_ringbuf_reserve(&stats_events, sizeof(*se), 0);
    if (!se) {
        bpf_d_printk("fs_io: stats_events ring buffer full, dropping event");
        return;
    }

    se->flags = k_event_stat_fs_io;
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
