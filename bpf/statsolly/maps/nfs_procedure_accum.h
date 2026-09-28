// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

#include <statsolly/types.h>

typedef struct nfs_procedure_key {
    // id of the io controller cgroup of the thread that started the RPC, 0 if unknown
    u64 cgroup_id;
    // address of the NFS server, as the RPC transport displays it
    unsigned char server[k_nfs_server_max_len];
    // name of the procedure, as the NFS client names it
    unsigned char procedure[k_nfs_procedure_max_len];
    // NFS protocol version (the version of the ONC RPC program)
    u32 version;
    // 0 on success, otherwise the errno (or NFSv4 error) that the RPC completed with
    u16 status;
    u8 _pad[2];
} nfs_procedure_key_t;

// Cumulative values: the kernel never resets them, userspace reads them periodically and
// computes the deltas.
typedef struct nfs_procedure_accum {
    u64 latency_count[k_disk_latency_max_buckets];
    u64 latency_sum_ns[k_disk_latency_max_buckets];
} nfs_procedure_accum_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1 << 12);
    __type(key, nfs_procedure_key_t);
    __type(value, nfs_procedure_accum_t);
    __uint(pinning, OBI_PIN_INTERNAL);
} nfs_procedure_accum SEC(".maps");
