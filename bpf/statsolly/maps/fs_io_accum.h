// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

#include <statsolly/fs_io.h>

// Kernel-side aggregation of the filesystem operations (fs_emit_agg), read
// and deleted by userspace (statagg). One map per histogram layout; the one
// not in use is created with one entry.
//
// Shared by all CPUs, not per CPU: keys are per container, volume, operation
// and errno, and a per-CPU copy of each would cost the value size times the
// possible CPUs. Updates are atomic. A plain HASH: a full map drops the new
// key's operations and counts them in fs_drops rather than evict a key
// userspace has not read.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 13);
    __type(key, struct fs_io_accum_key);
    __type(value, struct fs_io_accum_val);
    __uint(pinning, OBI_PIN_INTERNAL);
} fs_io_accum SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 13);
    __type(key, struct fs_io_accum_key);
    __type(value, struct fs_io_accum_exp_val);
    __uint(pinning, OBI_PIN_INTERNAL);
} fs_io_accum_exp SEC(".maps");

// A zeroed value, for creating keys of either map: never written, so one
// copy serves every CPU.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct fs_io_accum_exp_val);
    __uint(pinning, OBI_PIN_INTERNAL);
} fs_accum_zero SEC(".maps");

// What the filesystem programs could not record, per enum fs_drop_reason.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, fs_drop_reasons);
    __type(key, u32);
    __type(value, u64);
    __uint(pinning, OBI_PIN_INTERNAL);
} fs_drops SEC(".maps");
