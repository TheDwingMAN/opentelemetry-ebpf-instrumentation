// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <statsolly/hist.h>

// NFS client RPC aggregation: the key and values the rpc_stats_latency
// programs count into, and the pure helpers that build them, kept free of
// kernel types and map access so bpf/tests can check them natively.

enum {
    // ONC RPC program number of NFS (RFC 1813, RFC 7530): the NFS client's
    // rpc_clnt has it in cl_prog; the NFSv3 ACL, lockd and mount clients do not.
    k_nfs_program = 100003,
    // Address families of rpc_xprt.addr.
    k_nfs_af_inet = 2,
    k_nfs_af_inet6 = 10,
};

// What one RPC attempt counts into. Every field is written, so the key has no
// uninitialized bytes: two attempts to the same server, procedure and status
// always hash the same.
struct nfs_rpc_key {
    // The pod attribution of the RPC (step 19): the submitting cgroup id
    // (cgroup v2) or thread tgid (cgroup v1, tk_owner); 0 when no pod
    // attribute is selected.
    u64 owner;
    // task->tk_msg.rpc_proc->p_statidx: the procedure number for NFSv2 and
    // NFSv3, the NFSPROC4_CLNT_* operation index for NFSv4.
    u16 statidx;
    // tk_client->cl_vers: 2, 3 or 4.
    u8 vers;
    // rpc_xprt.addr's family: k_nfs_af_inet, k_nfs_af_inet6, or 0 when the
    // transport has another one (the address is then left out).
    u8 family;
    // tk_status when it is an error (< 0), else 0; always 0 when the errors
    // metric is off, so errors never split the other metrics' keys.
    s32 status;
    // The server address, network byte order: 4 bytes for IPv4, 16 for IPv6.
    u8 addr[16];
    // sin6_scope_id of an IPv6 server: the kernel prints it after a
    // link-local address in the mount option addr=, which the filesystem
    // metrics' server.address comes from.
    u32 scope_id;
    unsigned char _pad[4];
};

// The value of a key with the explicit bucket layout. The histogram is the
// execute time of each attempt (rpc_stats_latency's execute argument, what
// mountstats sums as "execute"); its count is the number of attempts.
struct nfs_rpc_val {
    u64 sum_ns;
    // Wire bytes of the attempt's call and reply (rq_xmit_bytes_sent and
    // rq_reply_bytes_recvd): headers and every procedure included, the same
    // fields /proc/self/mountstats sums. StatNFSClientIO reads the two
    // words as separate series; nothing else in the key tells them apart.
    u64 tx_bytes;
    u64 rx_bytes;
    // Retransmissions: rq_ntrans - 1 per attempt.
    u64 retrans;
    u32 bkt[k_stat_hist_max_bounds + 1];
    unsigned char _pad[4];
};

// The value of a key with the exponential bucket layout.
struct nfs_rpc_exp_val {
    u64 sum_ns;
    u64 tx_bytes;
    u64 rx_bytes;
    u64 retrans;
    u32 bkt[k_stat_hist_exp_max_bounds + 1];
    unsigned char _pad[4];
};

// nfs_rpc_status returns what the key records of tk_status: the error, or 0.
// A successful READ or WRITE leaves its payload byte count in tk_status and a
// READ at end of file leaves 0 (S0-c); the kernel itself counts only negative
// statuses as errors. Negative statuses are not always errnos: an NFSv3
// JUKEBOX arrives as -528 (EJUKEBOX), and NFSv4 statuses nfs4_stat_to_errno
// does not map arrive as -NFS4ERR_* (-10008, NFS4ERR_DELAY).
static __always_inline s32 nfs_rpc_status(const s32 tk_status, const bool want_status) {
    if (!want_status || tk_status >= 0) {
        return 0;
    }
    return tk_status;
}

// nfs_rpc_retrans returns the retransmissions of an attempt from its
// rq_ntrans, the number of times the request was sent: the kernel's own
// om_ntrans adds max(rq_ntrans, 1) per attempt, so a request that was never
// sent (0) has retransmitted nothing either.
static __always_inline u64 nfs_rpc_retrans(const s32 ntrans) {
    if (ntrans <= 1) {
        return 0;
    }
    return (u64)(ntrans - 1);
}

// nfs_rpc_execute returns the execute time as a count of nanoseconds. It is a
// ktime_t difference and never negative; a negative one still counts as an
// attempt, of 0 ns, so the attempt count stays equal to mountstats' ops.
static __always_inline u64 nfs_rpc_execute(const s64 execute) {
    return execute < 0 ? 0 : (u64)execute;
}
