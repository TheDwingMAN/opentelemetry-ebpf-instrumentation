// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_core_read.h>

// The cgroup a bio is charged to: bio->bi_blkg->blkcg->css.cgroup->kn->id,
// the cgroup v2 id that bpf_get_current_cgroup_id() returns for the tasks of
// that cgroup and the inode of its directory (S0-d). It is the blkcg, not the
// task running the program: requests are often issued by kernel threads
// (kblockd, the dm-thin pool worker, the writeback flushers), whose own
// cgroup is the root, while the bio keeps its owner. A request's first bio
// stands for all of it: the block layer merges only bios of the same blkg
// (blk_cgroup_mergeable).
//
// 0 when there is none: a kernel without CONFIG_BLK_CGROUP has no bi_blkg,
// and its relocation would be an invalid instruction the verifier rejects,
// taking the whole object down (v2 bpf/statsolly/cgroup_names.h, commit
// b1dfc046f), so it is read only behind bpf_core_field_exists; a request
// without a bio (a flush) and driver passthrough have no blkg. Before Linux
// 5.5 kernfs_node.id was a union, which the relocation does not match: no
// cgroup there either, rather than a failed load.

// blk_bio_cgid_btf reads it with direct loads, for tp_btf.
static __always_inline u64 blk_bio_cgid_btf(const struct bio *const bio) {
    if (!bpf_core_field_exists(struct bio, bi_blkg) || !bio) {
        return 0;
    }
    const struct blkcg_gq *const blkg = bio->bi_blkg;
    if (!blkg) {
        return 0;
    }
    const struct kernfs_node *const kn = blkg->blkcg->css.cgroup->kn;
    if (!kn || !bpf_core_field_exists(kn->id)) {
        return 0;
    }
    return kn->id;
}

// blk_bio_cgid reads it through bpf_probe_read_kernel, for raw_tp.
static __always_inline u64 blk_bio_cgid(const struct bio *const bio) {
    if (!bpf_core_field_exists(struct bio, bi_blkg) || !bio) {
        return 0;
    }
    const struct blkcg_gq *const blkg = BPF_CORE_READ(bio, bi_blkg);
    if (!blkg) {
        return 0;
    }
    const struct kernfs_node *const kn = BPF_CORE_READ(blkg, blkcg, css.cgroup, kn);
    if (!kn || !bpf_core_field_exists(kn->id)) {
        return 0;
    }
    return BPF_CORE_READ(kn, id);
}
