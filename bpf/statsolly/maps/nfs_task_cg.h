// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

// The cgroup v2 id of the thread that started each NFS RPC task (step 19):
// rpc_execute() -> rpc_set_active() -> trace_rpc_task_begin() runs in that
// thread, before an asynchronous task hands off to rpciod, so it names the
// submitter even though rpc_stats_latency usually runs in rpciod. Entries
// are overwritten on every begin (a JUKEBOX/DELAY retry reuses the task
// without calling rpc_execute again, so its stored id stays valid), and a
// completed task's entry is simply never read again: there is no delete
// hook for an RPC task, so this is the one LRU map a statagg source never
// is (bpf/statsolly/nfs_rpc.c; it is a side table, read by task pointer, not
// a source the Reader polls).
//
// Sizing: every completed RPC leaves an entry (nothing deletes it, and
// rpc_stats_latency fires once per attempt on a task a retry reuses), so the
// LRU is churned at the RPC rate and an entry lives only entries/rate: 16384
// would be 150-300 ms at 50-100k RPC/s, shorter than a slow or hung server's
// reply. The declared size is the minimum; userspace sets 16 times it (1<<18)
// when a pod attribute is selected and a single entry otherwise
// (prepareNFSSpec). A miss is counted in nfs_task_cg_misses and warned about.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1 << 14);
    __type(key, u64);
    __type(value, u64);
    __uint(pinning, OBI_PIN_INTERNAL);
} nfs_task_cg SEC(".maps");

// Attempts whose owner could not be read because nfs_task_cg had no entry
// for the task: evicted under CPU pressure, or the task started before the
// begin program attached.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
    __uint(pinning, OBI_PIN_INTERNAL);
} nfs_task_cg_misses SEC(".maps");
