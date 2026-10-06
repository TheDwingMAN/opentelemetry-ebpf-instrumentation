// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#pragma once

#include <bpfcore/vmlinux.h>
// The Go StatType* constants in pkg/internal/statsolly/ebpf/stat.go are derived from this enum
enum stat_type : u8 {
    k_stat_type_tcp_rtt = 1,
    k_stat_type_tcp_failed_connection = 2,
    k_stat_type_tcp_retransmit = 3,
    k_stat_type_tcp_io = 4,
    k_stat_type_tcp_successful_connection = 5,
    k_stat_type_block_io = 6,
    k_stat_type_fs_io = 7,
    // NFS client RPCs: aggregated in the kernel (nfs_rpc.c), never on the ring buffer.
    k_stat_type_nfs_rpc = 8,
};

// batch size used in tcp io metric
enum {
    k_tcp_io_batch_size = 10,
};

enum tcp_handshake_role : u8 {
    role_unknown = 0,
    role_client = 1,
    role_server = 2,
};

enum tcp_fail_reason : u8 {
    reason_unknown = 0,
    reason_connection_refused = 1,
    reason_connection_reset = 2,
    reason_timed_out = 3,
    reason_host_unreachable = 4,
    reason_net_unreachable = 5,
    reason_other = 255,
};

enum network_io_direction : u8 {
    direction_receive = 1,
    direction_transmit = 2,
};

// What a block request was. Flushes and discards move no data to or from the
// media, so they have metrics of their own rather than a direction.
enum blk_io_op : u8 {
    blk_op_read = 0,
    blk_op_write = 1,
    blk_op_flush = 2,
    blk_op_discard = 3,
};

typedef struct block_io {
    u8 flags; // Must be first, we use it to tell what kind of event we have on the ring buffer
    enum blk_io_op op; // the request's kind, classified at block_rq_issue
    unsigned char _pad[2];
    u32 dev;        // kernel dev_t (major<<20 | minor)
    u64 latency_ns; // issue -> complete (service time)
    u64 queue_ns;   // insert -> issue (queue wait time)
    u64 bytes;
    s32 error;    // completion tracepoint's error field: 0 or -errno
    u32 inflight; // requests still in flight on this device after this completion
    u32 part_dev; // partition dev_t; 0 for whole-disk I/O and until partitions are resolved
    unsigned char _pad2[4];
} block_io_t;

// Force struct into the ELF for automatic creation of Golang struct
const block_io_t *unused_block_io __attribute__((unused));

enum fs_type : u8 {
    fs_type_unknown = 0,
    fs_type_nfs = 1,
    fs_type_ceph = 2,
    fs_type_cifs = 3,
    fs_type_fuse = 4,
    fs_type_ext4 = 5,
    fs_type_xfs = 6,
    fs_type_btrfs = 7,
};

enum fs_op : u8 {
    fs_op_read = 0,
    fs_op_write = 1,
    fs_op_fsync = 2,
    fs_op_fdatasync = 3, // fdatasync(2): flush data without metadata
    fs_op_sync = 4,
    fs_op_syncfs = 5,
    fs_op_sync_file_range = 6,
};

typedef struct fs_io {
    u8 flags; // Must be first, we use it to tell what kind of event we have on the ring buffer
    enum fs_type fs;
    enum fs_op op;
    unsigned char _pad[1];
    u32 s_dev; // superblock dev_t; anonymous (major 0) for network filesystems
    u32 host_pid;
    u32 pid_ns;
    u64 latency_ns;
    u64 bytes;
    s32 error; // 0 on success, or -errno from the read/write implementation
    unsigned char _pad2[4];
    // Inode of the root directory of the mount the file was reached through.
    // Several volumes can share one superblock (NFS subdirectories of one
    // export); each is mounted at its own root, which tells them apart.
    u64 root_ino;
} fs_io_t;

// Force struct into the ELF for automatic creation of Golang struct
const fs_io_t *unused_fs_io __attribute__((unused));
