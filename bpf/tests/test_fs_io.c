// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Run from repo root:
//   make -C bpf/tests test_fs_io && bpf/tests/test_fs_io
// Run from bpf/tests:
//   make test_fs_io && ./test_fs_io

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <statsolly/fs_io.h>

static unsigned int failed_assertions;

static void assert_true(bool condition, const char *message) {
    if (condition) {
        printf("PASS: %s\n", message);
        return;
    }

    failed_assertions++;
    printf("FAIL: %s\n", message);
}

static void test_ret_recorded(void) {
    assert_true(fs_ret_recorded(fs_op_read, 4096), "a read of 4096 bytes is recorded");
    assert_true(!fs_ret_recorded(fs_op_read, 0), "a read at EOF is not");
    assert_true(!fs_ret_recorded(fs_op_write, -k_eiocbqueued), "a queued async write is not");
    assert_true(fs_ret_recorded(fs_op_write, -5), "a failed write is");
    assert_true(fs_ret_recorded(fs_op_fsync, 0), "a successful fsync is");
    assert_true(fs_ret_recorded(fs_op_fdatasync, 0), "a successful fdatasync is");
    assert_true(fs_ret_recorded(fs_op_fsync, -5), "a failed fsync is");
}

static void test_is_sync_op(void) {
    assert_true(!fs_is_sync_op(fs_op_read), "read is not a sync op");
    assert_true(!fs_is_sync_op(fs_op_write), "write is not a sync op");
    assert_true(fs_is_sync_op(fs_op_fsync), "fsync is a sync op");
    assert_true(fs_is_sync_op(fs_op_fdatasync), "fdatasync is a sync op");
    assert_true(fs_is_sync_op(fs_op_sync), "sync is a sync op");
    assert_true(fs_is_sync_op(fs_op_syncfs), "syncfs is a sync op");
    assert_true(fs_is_sync_op(fs_op_sync_file_range), "sync_file_range is a sync op");
}

static void test_fs_type_from_sb(void) {
    assert_true(fs_type_from_sb(0x6969) == fs_type_nfs, "NFS_SUPER_MAGIC");
    assert_true(fs_type_from_sb(0x00c36400) == fs_type_ceph, "CEPH_SUPER_MAGIC");
    assert_true(fs_type_from_sb(0xff534d42) == fs_type_cifs, "CIFS_SUPER_MAGIC");
    assert_true(fs_type_from_sb(0x65735546) == fs_type_fuse, "FUSE_SUPER_MAGIC");
    assert_true(fs_type_from_sb(0xef53) == fs_type_ext4,
                "EXT4_SUPER_MAGIC (shared with ext2/ext3)");
    assert_true(fs_type_from_sb(0x58465342) == fs_type_xfs, "XFS_SUPER_MAGIC");
    assert_true(fs_type_from_sb(0x9123683e) == fs_type_btrfs, "BTRFS_SUPER_MAGIC");
    assert_true(fs_type_from_sb(0x01021994) == fs_type_unknown,
                "tmpfs magic is unknown (fs_probe_entry_generic drops it)");
    assert_true(fs_type_from_sb(0) == fs_type_unknown, "no superblock (sync(2)) is unknown");
}

static void test_sync_file_range_waits(void) {
    assert_true(!sync_file_range_waits(k_sync_file_range_write),
                "a pure SYNC_FILE_RANGE_WRITE hint does not wait");
    assert_true(!sync_file_range_waits(0), "no flags does not wait");
    assert_true(sync_file_range_waits(k_sync_file_range_wait_before), "WAIT_BEFORE waits");
    assert_true(sync_file_range_waits(k_sync_file_range_wait_after), "WAIT_AFTER waits");
    assert_true(sync_file_range_waits(k_sync_file_range_wait_before | k_sync_file_range_write |
                                      k_sync_file_range_wait_after),
                "WAIT_BEFORE|WRITE|WAIT_AFTER waits");
}

static void test_accum_err(void) {
    assert_true(fs_accum_err(0) == 0, "success has no errno");
    assert_true(fs_accum_err(4096) == 0, "bytes are no errno");
    assert_true(fs_accum_err(-5) == 5, "-EIO is EIO");
    assert_true(fs_accum_err(-512) == 512, "-ERESTARTSYS keeps its kernel-internal errno");
    assert_true(fs_accum_err(-4095) == 4095, "MAX_ERRNO fits");
    assert_true(fs_accum_err(-100000) == 0xffff, "no errno overflows into another");
}

static void test_key_init_zeroes_padding(void) {
    struct fs_io_accum_key a, b;
    memset(&a, 0xaa, sizeof(a));
    memset(&b, 0x55, sizeof(b));
    const struct fs_start_val start = {
        .ts = 1, .root_ino = 42, .s_dev = 0x800001, .fs = fs_type_xfs, .op = fs_op_write};

    fs_accum_key_init(&a, 7, &start, 4026531836u, -28);
    fs_accum_key_init(&b, 7, &start, 4026531836u, -28);
    assert_true(memcmp(&a, &b, sizeof(a)) == 0, "equal keys are equal bytes, padding included");
    assert_true(sizeof(a) == 32, "the key is 32 bytes");
    assert_true(a.cgid == 7 && a.root_ino == 42 && a.s_dev == 0x800001 && a.pid_ns == 4026531836u,
                "identity fields");
    assert_true(a.fs == fs_type_xfs && a.op == fs_op_write && a.err == 28, "operation and errno");
}

static void test_value_layouts(void) {
    assert_true(sizeof(struct fs_io_accum_val) == 152,
                "explicit value: 2 u64, 33 u32, sample tgid");
    assert_true(sizeof(struct fs_io_accum_exp_val) == 536,
                "exponential value: 2 u64, 129 u32, sample tgid");
    assert_true(sizeof(struct fs_start_val) == 24, "start value");
}

static void test_nesting(void) {
    const u64 now = 100ULL * 1000000000ULL;
    struct fs_start_val cur = {};

    assert_true(!fs_start_nest(NULL, now), "no start: an outermost operation");
    assert_true(!fs_start_nest(&cur, now), "a cleared task storage start: outermost");

    cur.ts = now - 1000;
    assert_true(fs_start_nest(&cur, now), "a start in flight: nested");
    assert_true(cur.depth == 1, "nesting counted");
    assert_true(fs_start_nest(&cur, now), "twice nested");
    assert_true(cur.depth == 2, "nesting counted twice");

    assert_true(fs_start_unnest(&cur) && cur.depth == 1, "inner exit counted out");
    assert_true(fs_start_unnest(&cur) && cur.depth == 0, "second inner exit counted out");
    assert_true(!fs_start_unnest(&cur), "the outermost exit records");

    struct fs_start_val orphan = {.ts = now - k_fs_start_stale_ns, .depth = 3};
    assert_true(!fs_start_nest(&orphan, now), "a stale start is an orphan, replaced");
    assert_true(orphan.depth == 3, "an orphan is not counted into");
}

int main(void) {
    test_ret_recorded();
    test_is_sync_op();
    test_fs_type_from_sb();
    test_sync_file_range_waits();
    test_accum_err();
    test_key_init_zeroes_padding();
    test_value_layouts();
    test_nesting();

    if (failed_assertions) {
        printf("%u assertion(s) failed\n", failed_assertions);
        return 1;
    }
    printf("All fs_io tests passed\n");
    return 0;
}
