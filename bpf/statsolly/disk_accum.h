// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_builtins.h>
#include <bpfcore/bpf_helpers.h>

#include <common/scratch_mem.h>

#include <statsolly/types.h>
#include <statsolly/maps/disk_io_accum.h>

// The latency histogram boundaries of block requests and bios. To be injected from userspace
// during eBPF program load & initialization.
volatile const u64 disk_latency_bounds_ns[k_disk_latency_max_bounds];
volatile const u32 disk_latency_bounds_len;

// The operation of block request and bio flags: the request flags start right after the
// REQ_OP_BITS-wide operation field.
enum { k_op_mask = (1U << __REQ_FAILFAST_DEV) - 1 };

// REQ_OP_ZONE_APPEND, which userspace finds in the kernel BTF: its value depends on the kernel
// version. 0 when the kernel has none.
volatile const u32 disk_req_op_zone_append;

SCRATCH_MEM_TYPED(disk_io_accum_init, disk_io_accum_t)

// The accumulation entry of a key in one of the disk accumulation maps, created zeroed if missing
static __always_inline disk_io_accum_t *lookup_or_init_accum(void *accum_map,
                                                             const disk_io_key_t *key) {
    disk_io_accum_t *accum = bpf_map_lookup_elem(accum_map, key);
    if (accum) {
        return accum;
    }
    disk_io_accum_t *init = disk_io_accum_init_mem();
    if (!init) {
        return 0;
    }
    bpf_memset(init, 0, sizeof(*init));
    // BPF_NOEXIST: another CPU may have created the entry since the lookup above
    bpf_map_update_elem(accum_map, key, init, BPF_NOEXIST);
    return bpf_map_lookup_elem(accum_map, key);
}
