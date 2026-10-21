// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_builtins.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_core_read.h>

#include <common/scratch_mem.h>

#include <statsolly/disk_io.h>
#include <statsolly/types.h>
#include <statsolly/maps/nfs_procedure_accum.h>

// Force structs into the ELF for automatic creation of Golang struct
const nfs_procedure_key_t *unused_nfs_procedure_key __attribute__((unused));
const nfs_procedure_accum_t *unused_nfs_procedure_accum __attribute__((unused));

SCRATCH_MEM_TYPED(nfs_procedure_accum_init, nfs_procedure_accum_t)

// ONC RPC program number of NFS
enum { k_nfs_program = 100003 };

// The sunrpc types are only known to the kernels whose BTF describes them. The probe checks for
// those that it reads first, so that the reads that CO-RE could not relocate are dead code that the
// verifier skips, and the program loads when every program is loaded, as in the verifier test. OBI
// itself loads a stub in its place where the vmlinux BTF lacks them.
static __always_inline bool has_rpc_types(void) {
    return bpf_core_type_exists(struct rpc_task) && bpf_core_type_exists(struct rpc_clnt) &&
           bpf_core_type_exists(struct rpc_procinfo) && bpf_core_type_exists(struct rpc_xprt);
}

static __always_inline bool is_nfs_task(const struct rpc_task *task) {
    return BPF_CORE_READ(task, tk_client, cl_prog) == k_nfs_program;
}

// The server as its first mount on the node names it: the NFS client names its transport after the
// host of server:/export, which is an address when the mount names the server by its address. The
// mounts of a server (address, protocol and version) share one nfs_client and its transport
// (nfs_match_client), so a later mount that names the server otherwise gets the first name.
static __always_inline void read_server(nfs_procedure_key_t *key, const struct rpc_task *task) {
    bpf_probe_read_kernel_str(
        key->server, sizeof(key->server), BPF_CORE_READ(task, tk_xprt, servername));
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

    nfs_procedure_key_t key = {
        .version = BPF_CORE_READ(task, tk_client, cl_vers),
        .status = nfs_status(BPF_CORE_READ(task, tk_status)),
    };
    read_server(&key, task);
    bpf_probe_read_kernel_str(
        key.procedure, sizeof(key.procedure), BPF_CORE_READ(task, tk_msg.rpc_proc, p_name));

    nfs_procedure_accum_t *accum = lookup_or_init_nfs_procedure_accum(&key);
    if (!accum) {
        return 0;
    }
    const u32 bucket = disk_latency_bucket(disk_latency_bounds_ns, execute_ns);
    __sync_fetch_and_add(&accum->latency_count[bucket], 1);
    __sync_fetch_and_add(&accum->latency_sum_ns, execute_ns);
    return 0;
}
