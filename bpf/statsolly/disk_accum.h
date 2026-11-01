// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_builtins.h>
#include <bpfcore/bpf_helpers.h>

#include <common/scratch_mem.h>

#include <statsolly/maps/disk_cgroup_names.h>
#include <statsolly/maps/disk_io_accum.h>

// What the block request and bio programs share: the load-time constants, the scratch memory of the
// accumulation entries and their lookup

// Set by userspace when block_rq_complete reports a blk_status_t instead of an errno
volatile const bool disk_status_is_blk_status;

// Set by userspace when the cgroups that the I/O is charged to are reported: otherwise the verifier
// leaves their reads out
volatile const bool disk_read_cgroup;

// The RQF_IO_STAT and RQF_FLUSH_SEQ request flags, which userspace finds in the kernel BTF: some
// kernels number them in an anonymous enum, and those that number them with macros get 0
volatile const u32 disk_rqf_io_stat;
volatile const u32 disk_rqf_flush_seq;

// REQ_OP_ZONE_APPEND, which userspace finds in the kernel BTF: its value depends on the kernel
// version
volatile const u32 disk_req_op_zone_append;

// Force structs into the ELF for automatic creation of Golang struct
const disk_io_key_t *unused_disk_io_key __attribute__((unused));
const disk_io_accum_t *unused_disk_io_accum __attribute__((unused));
const disk_cgroup_name_t *unused_disk_cgroup_name __attribute__((unused));

SCRATCH_MEM_TYPED(disk_io_accum_init, disk_io_accum_t)

// The operation of a block request is in the bits of its flags below the first request flag
enum { k_op_mask = (1U << __REQ_FAILFAST_DEV) - 1 };

static __always_inline disk_io_accum_t *lookup_or_init_accum(const disk_io_key_t *key) {
    disk_io_accum_t *accum = bpf_map_lookup_elem(&disk_io_accum, key);
    if (accum) {
        return accum;
    }
    disk_io_accum_t *init = disk_io_accum_init_mem();
    if (!init) {
        return 0;
    }
    bpf_memset(init, 0, sizeof(*init));
    // BPF_NOEXIST: another CPU may have created the entry since the lookup above
    bpf_map_update_elem(&disk_io_accum, key, init, BPF_NOEXIST);
    return bpf_map_lookup_elem(&disk_io_accum, key);
}
