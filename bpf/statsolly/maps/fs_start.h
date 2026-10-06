// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

#include <statsolly/fs_io.h>

// The start of each thread's filesystem operation in flight, in one of two
// maps. fentry/fexit programs keep it in the thread's task storage when the
// kernel lets them (fs_task_btf): no hash lookup, and the kernel frees it
// when the thread exits, so a thread that dies mid-call leaves nothing
// behind. kprobe programs cannot reach task storage, and use fs_start.

// Keyed by pid_tgid. A plain HASH, not an LRU, so a live start is never
// evicted: a start whose exit never runs (a thread killed inside a hung RPC,
// a wedged FUSE daemon) is deleted by userspace once it is 10 minutes old,
// and a start that finds the map full is counted in fs_drops.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 14);
    __type(key, u64);
    __type(value, struct fs_start_val);
    __uint(pinning, OBI_PIN_INTERNAL);
} fs_start SEC(".maps");

// The same per thread, in task storage. Its value is never deleted: the exit
// sets ts to 0.
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct fs_start_val);
    __uint(pinning, OBI_PIN_INTERNAL);
} fs_start_task SEC(".maps");
