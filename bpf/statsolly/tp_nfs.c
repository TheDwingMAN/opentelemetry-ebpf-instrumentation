// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_builtins.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_core_read.h>
#include <bpfcore/bpf_tracing.h>

#include <common/scratch_mem.h>

#include <statsolly/cgroup_names.h>
#include <statsolly/disk_io.h>
#include <statsolly/types.h>
#include <statsolly/maps/nfs_io_accum.h>
#include <statsolly/maps/nfs_procedure_accum.h>
#include <statsolly/maps/nfs_task_cgroup.h>

// To be injected from userspace during eBPF program load & initialization.
volatile const u64 nfs_latency_bounds_ns[k_disk_latency_max_bounds];
volatile const u32 nfs_latency_bounds_len;

SCRATCH_MEM_TYPED(nfs_procedure_accum_init, nfs_procedure_accum_t)

// Force structs into the ELF for automatic creation of Golang struct
const nfs_procedure_key_t *unused_nfs_procedure_key __attribute__((unused));
const nfs_procedure_accum_t *unused_nfs_procedure_accum __attribute__((unused));
const nfs_io_key_t *unused_nfs_io_key __attribute__((unused));

// ONC RPC program number of NFS
enum { k_nfs_program = 100003 };

// The sunrpc and nfs types are only known to the kernels whose BTF describes them. The probes
// check for them first, so that the reads that CO-RE could not relocate are dead code that the
// verifier skips, and the programs load anyway: userspace doesn't attach them then.
static __always_inline bool has_rpc_types(void) {
    return bpf_core_type_exists(struct rpc_task);
}

static __always_inline bool has_pgio_types(void) {
    return bpf_core_type_exists(struct rpc_task) && bpf_core_type_exists(struct nfs_pgio_header);
}

static __always_inline bool is_nfs_task(const struct rpc_task *task) {
    return BPF_CORE_READ(task, tk_client, cl_prog) == k_nfs_program;
}

static __always_inline u64 nfs_task_cgroup_id(const struct rpc_task *task) {
    const u64 task_addr = (u64)task;
    const u64 *cgroup_id = bpf_map_lookup_elem(&nfs_task_cgroup, &task_addr);
    return cgroup_id ? *cgroup_id : 0;
}

static __always_inline void read_server(unsigned char *server, const struct rpc_task *task) {
    // address_strings is indexed by enum rpc_display_format_t, whose RPC_DISPLAY_ADDR is 0
    bpf_probe_read_kernel_str(
        server, k_nfs_server_max_len, BPF_CORE_READ(task, tk_xprt, address_strings[0]));
}

// The status of a completed RPC task: 0 on success, otherwise its errno or NFSv4 error
static __always_inline u16 nfs_status(const s32 tk_status) {
    if (tk_status >= 0) {
        return 0;
    }
    return (u16)(-tk_status);
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

// rpc_task_begin(task, action) fires when a thread starts running an RPC task: the thread that
// the RPC is charged to.
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
    if (!cgrp) {
        return 0;
    }
    const u64 id = cgroup_id_of(cgrp);
    const u64 task_addr = (u64)task;
    bpf_map_update_elem(&nfs_task_cgroup, &task_addr, &id, BPF_ANY);
    record_cgroup_name(id, cgrp);
    return 0;
}

// rpc_stats_latency(task, backlog, rtt, execute) fires when an RPC task completes. execute is the
// time from the start of the task to its completion, as the NFS client counts it in
// /proc/self/mountstats.
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
        .cgroup_id = nfs_task_cgroup_id(task),
        .version = BPF_CORE_READ(task, tk_client, cl_vers),
        .status = nfs_status(BPF_CORE_READ(task, tk_status)),
    };
    read_server(key.server, task);
    bpf_probe_read_kernel_str(
        key.procedure, sizeof(key.procedure), BPF_CORE_READ(task, tk_msg.rpc_proc, p_name));

    nfs_procedure_accum_t *accum = lookup_or_init_nfs_procedure_accum(&key);
    if (!accum) {
        return 0;
    }
    const u32 bucket =
        disk_latency_bucket(nfs_latency_bounds_ns, nfs_latency_bounds_len, execute_ns);
    if (bucket >= k_disk_latency_max_buckets) {
        return 0;
    }
    __sync_fetch_and_add(&accum->latency_count[bucket], 1);
    __sync_fetch_and_add(&accum->latency_sum_ns[bucket], execute_ns);
    return 0;
}

// The bytes that a read or write RPC transferred, from its nfs_pgio_header. res.count is a u32 or
// a u64, depending on the kernel version.
static __always_inline u64 pgio_bytes(const struct nfs_pgio_header *hdr) {
    if (bpf_core_field_size(hdr->res.count) == sizeof(u32)) {
        u32 count = 0;
        bpf_core_read(&count, sizeof(count), &hdr->res.count);
        return count;
    }
    u64 count = 0;
    bpf_core_read(&count, sizeof(count), &hdr->res.count);
    return count;
}

static __always_inline void nfs_io_done(const struct rpc_task *task,
                                        const struct nfs_pgio_header *hdr,
                                        const enum network_io_direction direction) {
    const u64 bytes = pgio_bytes(hdr);
    if (bytes == 0) {
        return;
    }
    nfs_io_key_t key = {
        .cgroup_id = nfs_task_cgroup_id(task),
        .direction = direction,
    };
    read_server(key.server, task);

    u64 *accum = bpf_map_lookup_elem(&nfs_io_accum, &key);
    if (!accum) {
        const u64 zero = 0;
        // BPF_NOEXIST: another CPU may have created the entry since the lookup above
        bpf_map_update_elem(&nfs_io_accum, &key, &zero, BPF_NOEXIST);
        accum = bpf_map_lookup_elem(&nfs_io_accum, &key);
        if (!accum) {
            return;
        }
    }
    __sync_fetch_and_add(accum, bytes);
}

// nfs_readpage_done(task, hdr) and nfs_writeback_done(task, hdr) fire when a read or write RPC
// completes, with the bytes that the server read or wrote.
SEC("raw_tracepoint/nfs_readpage_done")
int obi_stats_raw_tp_nfs_readpage_done(struct bpf_raw_tracepoint_args *ctx) {
    if (!has_pgio_types()) {
        return 0;
    }
    nfs_io_done((const struct rpc_task *)ctx->args[0],
                (const struct nfs_pgio_header *)ctx->args[1],
                direction_receive);
    return 0;
}

SEC("raw_tracepoint/nfs_writeback_done")
int obi_stats_raw_tp_nfs_writeback_done(struct bpf_raw_tracepoint_args *ctx) {
    if (!has_pgio_types()) {
        return 0;
    }
    nfs_io_done((const struct rpc_task *)ctx->args[0],
                (const struct nfs_pgio_header *)ctx->args[1],
                direction_transmit);
    return 0;
}
