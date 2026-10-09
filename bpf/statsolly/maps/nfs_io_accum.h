// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

#include <statsolly/types.h>

typedef struct nfs_io_key {
    // id of the io controller cgroup of the thread that started the RPC, 0 if unknown
    u64 cgroup_id;
    // name of the NFS server, as its first mount on the node names it (see read_server)
    unsigned char server[k_nfs_server_max_len];
    // receive for reads, transmit for writes
    enum network_io_direction direction;
    u8 _pad[7];
} nfs_io_key_t;

// Cumulative bytes: the kernel never resets them, userspace reads them periodically and computes
// the deltas. A plain hash map, like disk_io_accum.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 12);
    __type(key, nfs_io_key_t);
    __type(value, u64);
    __uint(pinning, OBI_PIN_INTERNAL);
} nfs_io_accum SEC(".maps");
