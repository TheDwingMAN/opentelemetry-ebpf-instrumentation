// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

struct fs_start_val {
    u64 ts;
    u64 root_ino;
    u32 s_dev;
    u32 host_pid;
    u32 pid_ns;
    u8 fs;
    u8 op;
    u8 depth;
    unsigned char _pad[1];
};

// Keyed by pid_tgid. Entries whose exit probe never fires -- a task killed
// inside a hung RPC, or a wedged FUSE daemon -- would orphan and fill a plain
// HASH; LRU_HASH evicts instead of failing writes once full.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1 << 14);
    __type(key, u64);
    __type(value, struct fs_start_val);
    __uint(pinning, OBI_PIN_INTERNAL);
} fs_start SEC(".maps");
