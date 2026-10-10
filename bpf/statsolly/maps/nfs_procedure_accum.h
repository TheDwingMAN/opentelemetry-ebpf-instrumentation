// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

#include <statsolly/types.h>

typedef struct nfs_procedure_key {
    // name of the NFS server, as its first mount on the node names it (see read_server)
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
    u64 latency_count[k_disk_latency_buckets];
    u64 latency_sum_ns;
} nfs_procedure_accum_t;

// A plain hash map, like disk_io_accum
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 12);
    __type(key, nfs_procedure_key_t);
    __type(value, nfs_procedure_accum_t);
    __uint(pinning, OBI_PIN_INTERNAL);
} nfs_procedure_accum SEC(".maps");
