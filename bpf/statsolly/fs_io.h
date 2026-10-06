// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <statsolly/hist.h>
#include <statsolly/types.h>

// Types and pure helpers of the filesystem programs, kept free of kernel
// types and map access so bpf/tests can check them natively.

// Kernel-internal completion marker (include/linux/errno.h), not a real
// failure: an async iocb was queued and will complete later on its own,
// without OBI observing that completion.
enum { k_eiocbqueued = 529 };

// An fs_start entry older than this is an orphan, not an outer operation: its
// exit probe never ran (a kretprobe missed for lack of instances, or a probe
// attached mid-call). Left alone, it would count every later call on that
// thread as nested and silence the thread for good.
#define k_fs_start_stale_ns (30ULL * 1000000000ULL)

// How completed operations leave the kernel: one ring buffer event each, or
// added into fs_io_accum (fs_io_accum_exp), which userspace reads.
enum fs_emit_kind : u8 {
    fs_emit_ringbuf = 0,
    fs_emit_agg = 1,
};

// Indexes of fs_drops: what the programs could not record.
enum fs_drop_reason : u32 {
    // fs_io_accum (or fs_io_accum_exp) was full: a new key's operation was
    // not counted.
    fs_drop_accum_full = 0,
    // The thread's start could not be stored (fs_start full, or no task
    // storage could be allocated): the operation was not timed.
    fs_drop_start = 1,
    fs_drop_reasons = 2,
};

// The start of an operation in flight on a thread: in fs_start, keyed by
// pid_tgid, or in the thread's fs_start_task storage. The PID and PID
// namespace are read at the exit, from the same thread.
struct fs_start_val {
    u64 ts; // 0: no operation in flight (task storage is never deleted)
    u64 root_ino;
    u32 s_dev;
    u8 fs;
    u8 op;
    u8 depth;
    unsigned char _pad[1];
};

// A key of fs_io_accum: what one container (cgroup) did on one mount with
// one operation and outcome. Keys are bounded by containers x volumes x
// operations x errnos, not by processes.
struct fs_io_accum_key {
    // bpf_get_current_cgroup_id(): the cgroup v2 id of the calling thread.
    // On a cgroup v1 host it is the root for every thread, and userspace
    // decorates by pid_ns and sample_tgid instead.
    u64 cgid;
    u64 root_ino;
    u32 s_dev;
    u32 pid_ns;
    u8 fs;
    u8 op;
    // errno of a failed operation, 0 on success.
    u16 err;
    unsigned char _pad[4];
};

// A value of fs_io_accum: the explicit layout's 33 buckets. The counting
// words (sums, then buckets) come first; sample_tgid is not counted.
struct fs_io_accum_val {
    u64 sum_ns;
    u64 bytes;
    u32 bkt[k_stat_hist_max_bounds + 1];
    // A host tgid that counted into the key lately: the pid path of a
    // cgroup v1 host (and the RWX fallback) resolves the key through it.
    u32 sample_tgid;
};

// fs_io_accum_val for the exponential layout's 129 buckets.
struct fs_io_accum_exp_val {
    u64 sum_ns;
    u64 bytes;
    u32 bkt[k_stat_hist_exp_max_bounds + 1];
    u32 sample_tgid;
};

// fs_is_sync_op reports the operations that return 0 on success: fsync,
// fdatasync and the step 14 syscalls (sync, syncfs, sync_file_range), which
// sit contiguously from fs_op_fsync through fs_op_sync_file_range.
static __always_inline bool fs_is_sync_op(const u8 op) {
    return op >= fs_op_fsync && op <= fs_op_sync_file_range;
}

// Magic numbers of include/uapi/linux/magic.h. The step 14 sync syscalls
// have no file_operations identity to classify the filesystem from, unlike
// the per-filesystem read/write/fsync probes (2.4): syncfs(2) and
// sync_file_range(2) classify generically from the superblock's s_magic.
enum fs_magic : u32 {
    k_fs_magic_nfs = 0x6969,
    k_fs_magic_ceph = 0x00c36400,
    k_fs_magic_cifs = 0xff534d42,
    k_fs_magic_fuse = 0x65735546,
    // ext2 and ext3 share this magic with ext4; only ext4 is a supported PV
    // filesystem (2.4), so a mount fs_dev_filter allows is never ext2/ext3.
    k_fs_magic_ext4 = 0xef53,
    k_fs_magic_xfs = 0x58465342,
    k_fs_magic_btrfs = 0x9123683e,
};

// fs_type_from_sb maps a superblock's s_magic to our enum fs_type,
// fs_type_unknown for a magic this table does not list (fsTypeStr then omits
// system.filesystem.type rather than guessing).
static __always_inline enum fs_type fs_type_from_sb(const u64 magic) {
    switch (magic) {
    case k_fs_magic_nfs:
        return fs_type_nfs;
    case k_fs_magic_ceph:
        return fs_type_ceph;
    case k_fs_magic_cifs:
        return fs_type_cifs;
    case k_fs_magic_fuse:
        return fs_type_fuse;
    case k_fs_magic_ext4:
        return fs_type_ext4;
    case k_fs_magic_xfs:
        return fs_type_xfs;
    case k_fs_magic_btrfs:
        return fs_type_btrfs;
    default:
        return fs_type_unknown;
    }
}

// include/uapi/linux/fs.h flags of sync_file_range(2)'s flags argument: not
// in vmlinux BTF, since they are preprocessor constants rather than a real
// kernel enum.
enum sync_file_range_flag : u32 {
    k_sync_file_range_wait_before = 1,
    k_sync_file_range_write = 2,
    k_sync_file_range_wait_after = 4,
};

// sync_file_range_waits reports whether flags asks sync_file_range(2) to
// wait for the I/O, the only calls worth recording (D7, step 14): a pure
// SYNC_FILE_RANGE_WRITE hint (PostgreSQL *_flush_after, RocksDB
// bytes_per_sync) returns long before the data reaches the device, so
// recording it would flood the series with near-zero, meaningless latencies.
static __always_inline bool sync_file_range_waits(const u32 flags) {
    return (flags & (k_sync_file_range_wait_before | k_sync_file_range_wait_after)) != 0;
}

// fs_ret_recorded reports whether an operation that returned ret is
// recorded: read/write treat ret == 0 as EOF and -EIOCBQUEUED as a deferred
// async completion, neither worth a record; a sync returns 0 on success,
// which must still be recorded.
static __always_inline bool fs_ret_recorded(const u8 op, const long ret) {
    return fs_is_sync_op(op) || (ret != 0 && ret != -k_eiocbqueued);
}

// fs_accum_err returns the errno of a key: 0 for success, else -ret, which
// is at most MAX_ERRNO (4095) for a kernel function's error return.
static __always_inline u16 fs_accum_err(const long ret) {
    if (ret >= 0) {
        return 0;
    }
    if (ret < -0xffff) {
        return 0xffff;
    }
    return (u16)(-ret);
}

// fs_accum_key_init fills every byte of key, padding included: the key is
// hashed as raw bytes.
static __always_inline void fs_accum_key_init(struct fs_io_accum_key *key,
                                              const u64 cgid,
                                              const struct fs_start_val *start,
                                              const u32 pid_ns,
                                              const long ret) {
    __builtin_memset(key, 0, sizeof(*key));
    key->cgid = cgid;
    key->root_ino = start->root_ino;
    key->s_dev = start->s_dev;
    key->pid_ns = pid_ns;
    key->fs = start->fs;
    key->op = start->op;
    key->err = fs_accum_err(ret);
}

// fs_start_nest reports whether an operation entering at now nests inside
// the one cur holds, on the same thread, and counts it if so: O_SYNC/O_DSYNC
// writes call the filesystem's fsync from inside the write (ext4, xfs, nfs,
// ceph, fuse: generic_write_sync). Only the outermost exit records. An
// entry older than k_fs_start_stale_ns is an orphan, replaced.
//
// The step 14 syscall probes (sync, syncfs, sync_file_range) share this same
// depth counter rather than a flag of their own (v2's from_syscall): they
// never nest with the fsync file_operations probes, since syncfs only
// reaches ->sync_fs (sync_filesystem), never ->fsync, and sync_file_range
// calls neither. A thread cannot be inside both kinds of start at once.
static __always_inline bool fs_start_nest(struct fs_start_val *cur, const u64 now) {
    if (!cur || cur->ts == 0 || now - cur->ts >= k_fs_start_stale_ns) {
        return false;
    }
    cur->depth++;
    return true;
}

// fs_start_unnest reports whether an exit belongs to a nested operation of
// cur, and counts it out if so.
static __always_inline bool fs_start_unnest(struct fs_start_val *cur) {
    if (cur->depth == 0) {
        return false;
    }
    cur->depth--;
    return true;
}
