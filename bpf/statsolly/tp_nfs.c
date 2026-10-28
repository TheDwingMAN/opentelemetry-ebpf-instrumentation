// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_builtins.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_core_read.h>

#include <common/scratch_mem.h>

#include <statsolly/cgroup_names.h>
#include <statsolly/disk_io.h>
#include <statsolly/types.h>
#include <statsolly/maps/nfs_io_accum.h>
#include <statsolly/maps/nfs_procedure_accum.h>
#include <statsolly/maps/nfs_procedure_cgroup_accum.h>
#include <statsolly/maps/nfs_task_cgroup.h>

// Set by userspace: the maps that the RPCs are counted in, the histogram of the node and the
// counters per workload
volatile const bool nfs_procedure_histogram;
volatile const bool nfs_procedure_counters;

// Force structs into the ELF for automatic creation of Golang struct
const nfs_procedure_key_t *unused_nfs_procedure_key __attribute__((unused));
const nfs_procedure_accum_t *unused_nfs_procedure_accum __attribute__((unused));
const nfs_procedure_cgroup_key_t *unused_nfs_procedure_cgroup_key __attribute__((unused));
const nfs_procedure_cgroup_accum_t *unused_nfs_procedure_cgroup_accum __attribute__((unused));
const nfs_io_key_t *unused_nfs_io_key __attribute__((unused));

SCRATCH_MEM_TYPED(nfs_procedure_accum_init, nfs_procedure_accum_t)

// ONC RPC program number of NFS
enum { k_nfs_program = 100003 };

// The sunrpc types are only known to the kernels whose BTF describes them. The probes check for
// those that they read first, so that the reads that CO-RE could not relocate are dead code that
// the verifier skips, and the programs load when every program is loaded, as in the verifier test.
// OBI itself loads stubs in their place where the vmlinux BTF lacks them.
static __always_inline bool has_rpc_types(void) {
    return bpf_core_type_exists(struct rpc_task) && bpf_core_type_exists(struct rpc_clnt) &&
           bpf_core_type_exists(struct rpc_procinfo) && bpf_core_type_exists(struct rpc_xprt);
}

static __always_inline bool has_pgio_types(void) {
    return has_rpc_types() && bpf_core_type_exists(struct nfs_pgio_header);
}

static __always_inline bool is_nfs_task(const struct rpc_task *task) {
    return BPF_CORE_READ(task, tk_client, cl_prog) == k_nfs_program;
}

// The server as its first mount on the node names it: the NFS client names its transport after the
// host of server:/export, which is an address when the mount names the server by its address. The
// mounts of a server (address, protocol and version) share one nfs_client and its transport
// (nfs_match_client), so a later mount that names the server otherwise gets the first name.
static __always_inline void read_server(unsigned char (*server)[k_nfs_server_max_len],
                                        const struct rpc_task *task) {
    bpf_probe_read_kernel_str(*server, sizeof(*server), BPF_CORE_READ(task, tk_xprt, servername));
}

static __always_inline nfs_procedure_accum_t *
lookup_or_init_nfs_procedure_accum(const nfs_procedure_key_t *key) {
    nfs_procedure_accum_t *accum = bpf_map_lookup_elem(&nfs_procedure_accum, key);
    if (accum) {
        return accum;
    }
    nfs_procedure_accum_t *init = nfs_procedure_accum_init_mem();
    if (!init) {
        return 0;
    }
    bpf_memset(init, 0, sizeof(*init));
    // BPF_NOEXIST: another CPU may have created the entry since the lookup above
    bpf_map_update_elem(&nfs_procedure_accum, key, init, BPF_NOEXIST);
    return bpf_map_lookup_elem(&nfs_procedure_accum, key);
}

static __always_inline void count_nfs_procedure(const nfs_procedure_key_t *key,
                                                const u64 execute_ns) {
    nfs_procedure_accum_t *accum = lookup_or_init_nfs_procedure_accum(key);
    if (!accum) {
        return;
    }
    const u32 bucket = disk_latency_bucket(disk_latency_bounds_ns, execute_ns);
    __sync_fetch_and_add(&accum->latency_count[bucket], 1);
    __sync_fetch_and_add(&accum->latency_sum_ns, execute_ns);
}

static __always_inline void count_nfs_procedure_cgroup(const nfs_procedure_cgroup_key_t *key,
                                                       const u64 execute_ns) {
    nfs_procedure_cgroup_accum_t *accum = bpf_map_lookup_elem(&nfs_procedure_cgroup_accum, key);
    if (!accum) {
        const nfs_procedure_cgroup_accum_t zero = {};
        // BPF_NOEXIST: another CPU may have created the entry since the lookup above
        bpf_map_update_elem(&nfs_procedure_cgroup_accum, key, &zero, BPF_NOEXIST);
        accum = bpf_map_lookup_elem(&nfs_procedure_cgroup_accum, key);
        if (!accum) {
            return;
        }
    }
    __sync_fetch_and_add(&accum->count, 1);
    __sync_fetch_and_add(&accum->sum_ns, execute_ns);
}

// The cgroup of the thread that started a task, or 0 when its start wasn't seen
static __always_inline u64 nfs_task_cgroup_id(const struct rpc_task *task) {
    const u64 task_addr = (u64)task;
    const nfs_task_cgroup_t *entry = bpf_map_lookup_elem(&nfs_task_cgroup, &task_addr);
    if (!entry) {
        return 0;
    }
    return nfs_charged_cgroup(entry->cgroup_id, entry->owner, (u32)BPF_CORE_READ(task, tk_owner));
}

// rpc_task_begin(task, action) fires when rpc_execute starts a task, before it queues an
// asynchronous task on rpciod: the current thread is the one that the RPC is charged to. A task
// that the client restarts doesn't begin again. Userspace attaches the program only when it reads
// the cgroups.
SEC("raw_tracepoint/rpc_task_begin")
int obi_stats_raw_tp_rpc_task_begin(struct bpf_raw_tracepoint_args *ctx) {
    if (!has_rpc_types()) {
        return 0;
    }
    const struct rpc_task *task = (const struct rpc_task *)ctx->args[0];
    if (!is_nfs_task(task)) {
        return 0;
    }
    struct cgroup *cgrp = current_io_cgroup();
    const u64 task_addr = (u64)task;
    const nfs_task_cgroup_t started = {
        .cgroup_id = cgroup_id_of(cgrp),
        .owner = (u32)BPF_CORE_READ(task, tk_owner),
    };
    nfs_task_cgroup_t *entry = bpf_map_lookup_elem(&nfs_task_cgroup, &task_addr);
    if (entry) {
        // in place: an update of an LRU entry would take a free node of the map, as an insert does
        *entry = started;
    } else {
        bpf_map_update_elem(&nfs_task_cgroup, &task_addr, &started, BPF_NOEXIST);
    }
    if (cgrp) {
        record_cgroup_name(started.cgroup_id, cgrp);
    }
    return 0;
}

// rpc_stats_latency(task, backlog, rtt, execute) fires when the RPC client counts a completed RPC
// in its statistics, as /proc/self/mountstats shows them. execute is the time from the start of the
// task to its completion: its execute time there. A task that the client restarts, as when the
// server asks it to retry later, is counted again, from its restart.
SEC("raw_tracepoint/rpc_stats_latency")
int obi_stats_raw_tp_rpc_stats_latency(struct bpf_raw_tracepoint_args *ctx) {
    if (!has_rpc_types()) {
        return 0;
    }
    const struct rpc_task *task = (const struct rpc_task *)ctx->args[0];
    if (!is_nfs_task(task)) {
        return 0;
    }
    const s64 execute_ns = (s64)ctx->args[3];
    if (execute_ns < 0) {
        return 0;
    }

    nfs_procedure_cgroup_key_t key = {
        .rpc =
            {
                .version = BPF_CORE_READ(task, tk_client, cl_vers),
                .status = nfs_status(BPF_CORE_READ(task, tk_status)),
            },
    };
    read_server(&key.rpc.server, task);
    bpf_probe_read_kernel_str(
        key.rpc.procedure, sizeof(key.rpc.procedure), BPF_CORE_READ(task, tk_msg.rpc_proc, p_name));

    // each map on its own, so that neither a full map of the counters nor a missing entry of the
    // histogram keeps the RPC from the other
    if (nfs_procedure_histogram) {
        count_nfs_procedure(&key.rpc, (u64)execute_ns);
    }
    if (nfs_procedure_counters) {
        key.cgroup_id = nfs_task_cgroup_id(task);
        count_nfs_procedure_cgroup(&key, (u64)execute_ns);
    }
    return 0;
}

// The bytes of a READ or WRITE, which the client adds to the server bytes of mountstats.
// nfs_readpage_done(task, hdr) and nfs_writeback_done(task, hdr) have these arguments from Linux
// 5.6 and RHEL 8.3: before, the first one is an inode, which fails is_nfs_task. res.count is a
// __u32 through Linux 5.9 and on RHEL 8, and a __u64 from Linux 5.10.
static __always_inline int nfs_io_done(const struct bpf_raw_tracepoint_args *ctx,
                                       const enum network_io_direction direction) {
    if (!has_pgio_types()) {
        return 0;
    }
    const struct rpc_task *task = (const struct rpc_task *)ctx->args[0];
    // LOCALIO and the pNFS block layouts complete their I/O without an RPC, on a zeroed task
    if (!is_nfs_task(task)) {
        return 0;
    }
    const struct nfs_pgio_header *hdr = (const struct nfs_pgio_header *)ctx->args[1];
    const u64 bytes = BPF_CORE_READ_BITFIELD_PROBED(hdr, res.count);
    if (bytes == 0) {
        return 0;
    }
    nfs_io_key_t key = {
        .cgroup_id = nfs_task_cgroup_id(task),
        .direction = direction,
    };
    read_server(&key.server, task);

    u64 *accum = bpf_map_lookup_elem(&nfs_io_accum, &key);
    if (!accum) {
        const u64 zero = 0;
        // BPF_NOEXIST: another CPU may have created the entry since the lookup above
        bpf_map_update_elem(&nfs_io_accum, &key, &zero, BPF_NOEXIST);
        accum = bpf_map_lookup_elem(&nfs_io_accum, &key);
        if (!accum) {
            return 0;
        }
    }
    __sync_fetch_and_add(accum, bytes);
    return 0;
}

SEC("raw_tracepoint/nfs_readpage_done")
int obi_stats_raw_tp_nfs_readpage_done(struct bpf_raw_tracepoint_args *ctx) {
    return nfs_io_done(ctx, direction_receive);
}

SEC("raw_tracepoint/nfs_writeback_done")
int obi_stats_raw_tp_nfs_writeback_done(struct bpf_raw_tracepoint_args *ctx) {
    return nfs_io_done(ctx, direction_transmit);
}
