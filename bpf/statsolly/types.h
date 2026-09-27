// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#pragma once

#include <bpfcore/vmlinux.h>
enum {
    k_event_stat_tcp_rtt = 1,               // StatTypeTCPRtt
    k_event_stat_tcp_failed_connection = 2, // StatTypeTCPFailedConnection
    k_event_stat_tcp_retransmit = 3,        // StatTypeTCPRetransmit
    k_event_stat_tcp_io = 4,                // StatTypeTCPIo
    k_event_stat_block_io = 5,              // StatTypeBlockIo
    k_event_stat_fs_io = 6,                 // StatTypeFsIo
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

enum blk_io_op : u8 {
    blk_op_read = 0,
    blk_op_write = 1,
};

typedef struct block_io {
    u8 flags; // Must be first, we use it to tell what kind of event we have on the ring buffer
    enum blk_io_op op; // derived from rwbs[0]
    unsigned char _pad[2];
    u32 dev;        // kernel dev_t (major<<20 | minor)
    u64 latency_ns; // issue -> complete (service time)
    u64 queue_ns;   // insert -> issue (queue wait time)
    u64 bytes;
    s32 error;    // completion tracepoint's error field: 0 or -errno
    u32 inflight; // requests still in flight on this device after this completion
} block_io_t;

// Force struct into the ELF for automatic creation of Golang struct
const block_io_t *unused_block_io __attribute__((unused));

enum fs_type : u8 {
    fs_type_unknown = 0,
    fs_type_nfs = 1,
    fs_type_ceph = 2,
    fs_type_cifs = 3,
    fs_type_fuse = 4,
};

enum fs_op : u8 {
    fs_op_read = 0,
    fs_op_write = 1,
    fs_op_fsync = 2,
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
} fs_io_t;

// Force struct into the ELF for automatic creation of Golang struct
const fs_io_t *unused_fs_io __attribute__((unused));
