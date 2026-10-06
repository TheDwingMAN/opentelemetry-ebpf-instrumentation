// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

#include <statsolly/nfs_rpc.h>

// NFS client RPC attempts per server, procedure and status, counted by the
// rpc_stats_latency programs and read, and deleted when idle, by userspace
// (statagg). One map per bucket layout: userspace loads the one it does not
// use with one entry. Plain HASH shared by every CPU, updated with atomics:
// NFS completes far fewer RPCs than a disk completes requests, and a
// per-CPU copy of each value on a 128-CPU node would cost 128 times the
// memory for no measurable gain. Never LRU: an evicted key would lose what it
// counted, and a full map counts its misses in nfs_rpc_drops instead.
// PinInternal, so a reload of the programs (the raw tracepoint fallback, a
// late attach) keeps counting into the maps userspace reads.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 12);
    __type(key, struct nfs_rpc_key);
    __type(value, struct nfs_rpc_val);
    __uint(pinning, OBI_PIN_INTERNAL);
} nfs_rpc_accum SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 12);
    __type(key, struct nfs_rpc_key);
    __type(value, struct nfs_rpc_exp_val);
    __uint(pinning, OBI_PIN_INTERNAL);
} nfs_rpc_accum_exp SEC(".maps");

// Attempts that could not be counted because the accumulator was full.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
    __uint(pinning, OBI_PIN_INTERNAL);
} nfs_rpc_drops SEC(".maps");
