// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_core_read.h>
#include <bpfcore/bpf_tracing.h>

#include <common/scratch_mem.h>

#include <statsolly/hist.h>
#include <statsolly/nfs_rpc.h>
#include <statsolly/maps/nfs_rpc_accum.h>
#include <statsolly/maps/nfs_task_cg.h>

// NFS client RPC metrics from the sunrpc tracepoint rpc_stats_latency(task,
// backlog, rtt, execute). rpc_exit_task fires it through rpc_count_iostats
// after rpc_task_end and before rpc_call_done, once per RPC attempt that got
// a request slot, so tk_status is the decode result of this attempt: the
// counts equal /proc/self/mountstats' ops and errors per procedure (S0-c).
// A server-requested retry (NFSv3 JUKEBOX, NFSv4 DELAY or GRACE) restarts the
// task after this point: each attempt is a sample of its own, and the attempt
// after a JUKEBOX includes the client's backoff in its execute time.
// rpc_count_iostats has already added req's rq_xmit_bytes_sent and
// rq_reply_bytes_recvd into mountstats by the time it calls us: the same
// counts, read straight off the request, back StatNFSClientIO.
//
// The same body builds as a BTF-typed tracepoint (tp_btf, the default: its
// pointer walks are plain loads) and as a raw tracepoint reading through
// BPF_CORE_READ, the fallback userspace loads when the tp_btf program cannot
// load or attach.

// Load-time constants, set by userspace.
// nfs_want_status: the errors metric is on, so the key keeps tk_status.
volatile const u8 nfs_want_status;
// nfs_hist_exp: count in the exponential bucket layout (nfs_rpc_accum_exp).
volatile const u8 nfs_hist_exp;
// nfs_key_owner: a pod attribute is selected on an NFS metric, so the key
// keeps an owner (step 19); otherwise it stays 0 and the begin program below
// is not even attached.
volatile const u8 nfs_key_owner;
// nfs_cgroup_v1: this host's cgroup v2 hierarchy is not delegated down to
// containers (S0-d: bpf_get_current_cgroup_id() would return the root for
// every task there), so the owner is the submitting thread's tgid
// (task->tk_owner) instead of its cgroup id.
volatile const u8 nfs_cgroup_v1;
// The histogram bounds of each layout, in nanoseconds, padded with U64_MAX.
volatile const u64 nfs_rpc_bounds_ns[k_stat_hist_max_bounds];
volatile const u64 nfs_rpc_exp_bounds_ns[k_stat_hist_exp_max_bounds];

// Force the key and value types into the ELF, for the Go layout tests.
const struct nfs_rpc_key *unused_nfs_rpc_key __attribute__((unused));
const struct nfs_rpc_val *unused_nfs_rpc_val __attribute__((unused));
const struct nfs_rpc_exp_val *unused_nfs_rpc_exp_val __attribute__((unused));

// The initial value of a new key, of either layout: too large for the BPF
// stack in the exponential one. Nothing writes to it, so it stays zeroed.
SCRATCH_MEM_TYPED(nfs_rpc_zero, struct nfs_rpc_exp_val)

static __always_inline void nfs_rpc_drop(void) {
    const u32 zero = 0;
    u64 *drops = bpf_map_lookup_elem(&nfs_rpc_drops, &zero);
    if (drops) {
        __sync_fetch_and_add(drops, 1);
    }
}

static __always_inline void nfs_task_cg_miss(void) {
    const u32 zero = 0;
    u64 *misses = bpf_map_lookup_elem(&nfs_task_cg_misses, &zero);
    if (misses) {
        __sync_fetch_and_add(misses, 1);
    }
}

// nfs_rpc_owner_v2 returns the cgroup id nfs_task_cg recorded for task_addr
// at rpc_task_begin (the submitting thread's cgroup), or 0, counted in
// nfs_task_cg_misses, when the begin program never ran for this task (not
// attached yet, or evicted under CPU pressure: both are rare, 2.5).
static __always_inline u64 nfs_rpc_owner_v2(const u64 task_addr) {
    const u64 *cgid = bpf_map_lookup_elem(&nfs_task_cg, &task_addr);
    if (!cgid) {
        nfs_task_cg_miss();
        return 0;
    }
    return *cgid;
}

// nfs_rpc_owner returns what the key's owner records for this attempt:
// 0 when no pod attribute is selected, else the cgroup v2 id (default) or
// the submitting thread's tgid on a cgroup v1 host, where cgroup ids never
// identify a container (2.5).
static __always_inline u64 nfs_rpc_owner(const u64 task_addr, const s32 tk_owner) {
    if (!nfs_key_owner) {
        return 0;
    }
    if (nfs_cgroup_v1) {
        return (u64)(u32)tk_owner;
    }
    return nfs_rpc_owner_v2(task_addr);
}

// nfs_rpc_value returns key's value in map, creating it zeroed when it is not
// there yet, or NULL, counted as a drop, when the map is full.
static __always_inline void *nfs_rpc_value(void *map, const struct nfs_rpc_key *key) {
    void *val = bpf_map_lookup_elem(map, key);
    if (val) {
        return val;
    }
    const void *init = nfs_rpc_zero_mem();
    if (!init) {
        return 0;
    }
    // BPF_NOEXIST: another CPU may have created the key since the lookup.
    bpf_map_update_elem(map, key, init, BPF_NOEXIST);
    val = bpf_map_lookup_elem(map, key);
    if (!val) {
        nfs_rpc_drop();
    }
    return val;
}

// nfs_rpc_count counts one attempt of key. The map is shared by every CPU,
// so every word is updated atomically.
static __always_inline void nfs_rpc_count(const struct nfs_rpc_key *key,
                                          const u64 execute_ns,
                                          const u64 retrans,
                                          const u64 tx_bytes,
                                          const u64 rx_bytes) {
    if (nfs_hist_exp) {
        struct nfs_rpc_exp_val *val = nfs_rpc_value(&nfs_rpc_accum_exp, key);
        if (!val) {
            return;
        }
        __sync_fetch_and_add(&val->sum_ns, execute_ns);
        __sync_fetch_and_add(&val->tx_bytes, tx_bytes);
        __sync_fetch_and_add(&val->rx_bytes, rx_bytes);
        if (retrans) {
            __sync_fetch_and_add(&val->retrans, retrans);
        }
        stat_hist_exp_add(val->bkt, stat_hist_exp_idx(nfs_rpc_exp_bounds_ns, execute_ns));
        return;
    }
    struct nfs_rpc_val *val = nfs_rpc_value(&nfs_rpc_accum, key);
    if (!val) {
        return;
    }
    __sync_fetch_and_add(&val->sum_ns, execute_ns);
    __sync_fetch_and_add(&val->tx_bytes, tx_bytes);
    __sync_fetch_and_add(&val->rx_bytes, rx_bytes);
    if (retrans) {
        __sync_fetch_and_add(&val->retrans, retrans);
    }
    stat_hist_add(val->bkt, stat_hist_idx(nfs_rpc_bounds_ns, execute_ns));
}

SEC("tp_btf/rpc_stats_latency")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_tp_btf_rpc_stats_latency,
             const struct rpc_task *task,
             ktime_t backlog,
             ktime_t rtt,
             ktime_t execute) {
    (void)ctx;
    (void)backlog;
    (void)rtt;
    // sunrpc is a module: on el9 the verifier marks the pointer arguments of
    // a module tracepoint maybe-NULL, and rejects the program unless it
    // checks them before the first dereference (S0-c). The pointers walked
    // from it need no check: a load through a NULL one reads 0.
    if (!task) {
        return 0;
    }
    const struct rpc_clnt *clnt = task->tk_client;
    if (clnt->cl_prog != k_nfs_program) {
        return 0;
    }
    const struct rpc_rqst *req = task->tk_rqstp;
    const struct rpc_xprt *xprt = req->rq_xprt;

    struct nfs_rpc_key key = {
        .owner = nfs_rpc_owner((u64)task, task->tk_owner),
        .statidx = (u16)task->tk_msg.rpc_proc->p_statidx,
        .vers = (u8)clnt->cl_vers,
        .status = nfs_rpc_status(task->tk_status, nfs_want_status),
    };
    const u16 family = xprt->addr.ss_family;
    if (family == k_nfs_af_inet) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)&xprt->addr;
        const u32 addr = sin->sin_addr.s_addr;
        __builtin_memcpy(key.addr, &addr, sizeof(addr));
        key.family = k_nfs_af_inet;
    } else if (family == k_nfs_af_inet6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)&xprt->addr;
        const u32 addr[4] = {
            sin6->sin6_addr.in6_u.u6_addr32[0],
            sin6->sin6_addr.in6_u.u6_addr32[1],
            sin6->sin6_addr.in6_u.u6_addr32[2],
            sin6->sin6_addr.in6_u.u6_addr32[3],
        };
        __builtin_memcpy(key.addr, addr, sizeof(addr));
        key.scope_id = sin6->sin6_scope_id;
        key.family = k_nfs_af_inet6;
    }

    nfs_rpc_count(&key,
                  nfs_rpc_execute(execute),
                  nfs_rpc_retrans(req->rq_ntrans),
                  (u64)req->rq_xmit_bytes_sent,
                  (u64)req->rq_reply_bytes_recvd);
    return 0;
}

SEC("raw_tracepoint/rpc_stats_latency")
int obi_stats_raw_tp_rpc_stats_latency(struct bpf_raw_tracepoint_args *ctx) {
    // Without the sunrpc types in the kernel BTF, the reads below cannot be
    // relocated: this makes them dead code, so the object still loads.
    // Userspace never attaches it then.
    if (!bpf_core_type_exists(struct rpc_task)) {
        return 0;
    }
    const struct rpc_task *task = (const struct rpc_task *)ctx->args[0];
    if (!task || BPF_CORE_READ(task, tk_client, cl_prog) != k_nfs_program) {
        return 0;
    }
    const struct rpc_rqst *req = BPF_CORE_READ(task, tk_rqstp);
    const struct rpc_xprt *xprt = BPF_CORE_READ(req, rq_xprt);

    struct nfs_rpc_key key = {
        .owner = nfs_rpc_owner((u64)task, BPF_CORE_READ(task, tk_owner)),
        .statidx = (u16)BPF_CORE_READ(task, tk_msg.rpc_proc, p_statidx),
        .vers = (u8)BPF_CORE_READ(task, tk_client, cl_vers),
        .status = nfs_rpc_status(BPF_CORE_READ(task, tk_status), nfs_want_status),
    };
    // One read of the largest address the key holds; its family says which.
    struct sockaddr_in6 sin6 = {};
    bpf_core_read(&sin6, sizeof(sin6), &xprt->addr);
    if (sin6.sin6_family == k_nfs_af_inet) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)&sin6;
        __builtin_memcpy(key.addr, &sin->sin_addr.s_addr, sizeof(sin->sin_addr.s_addr));
        key.family = k_nfs_af_inet;
    } else if (sin6.sin6_family == k_nfs_af_inet6) {
        __builtin_memcpy(key.addr, &sin6.sin6_addr, sizeof(sin6.sin6_addr));
        key.scope_id = sin6.sin6_scope_id;
        key.family = k_nfs_af_inet6;
    }

    nfs_rpc_count(&key,
                  nfs_rpc_execute((s64)ctx->args[3]),
                  nfs_rpc_retrans(BPF_CORE_READ(req, rq_ntrans)),
                  (u64)BPF_CORE_READ(req, rq_xmit_bytes_sent),
                  (u64)BPF_CORE_READ(req, rq_reply_bytes_recvd));
    return 0;
}

// rpc_task_begin(task, action) fires when a thread starts running an RPC
// task (rpc_execute, called from rpc_run_task before an asynchronous task
// may hand off to rpciod): the thread this attempt is charged to on cgroup
// v2 (step 19). Loaded and attached only when nfs_key_owner is set and the
// host is not cgroup v1 (nfs_cgroup_v1): on cgroup v1,
// bpf_get_current_cgroup_id() is the root for every task (S0-d), so the
// owner comes from tk_owner at rpc_stats_latency instead and this program
// is never attached.
SEC("tp_btf/rpc_task_begin")
// NOLINTNEXTLINE(readability-non-const-parameter)
int BPF_PROG(obi_stats_tp_btf_rpc_task_begin, const struct rpc_task *task, const void *action) {
    (void)ctx;
    (void)action;
    if (!task) {
        return 0;
    }
    const struct rpc_clnt *clnt = task->tk_client;
    if (clnt->cl_prog != k_nfs_program) {
        return 0;
    }
    const u64 task_addr = (u64)task;
    const u64 cgid = bpf_get_current_cgroup_id();
    bpf_map_update_elem(&nfs_task_cg, &task_addr, &cgid, BPF_ANY);
    return 0;
}

SEC("raw_tracepoint/rpc_task_begin")
int obi_stats_raw_tp_rpc_task_begin(struct bpf_raw_tracepoint_args *ctx) {
    if (!bpf_core_type_exists(struct rpc_task)) {
        return 0;
    }
    const struct rpc_task *task = (const struct rpc_task *)ctx->args[0];
    if (!task || BPF_CORE_READ(task, tk_client, cl_prog) != k_nfs_program) {
        return 0;
    }
    const u64 task_addr = (u64)task;
    const u64 cgid = bpf_get_current_cgroup_id();
    bpf_map_update_elem(&nfs_task_cg, &task_addr, &cgid, BPF_ANY);
    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
