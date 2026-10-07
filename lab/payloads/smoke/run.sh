#!/bin/bash
# Smoke payload: basic kernel facts + the block-layer feasibility probe.
echo "uname -r: $(uname -r)"
if [ -e /sys/kernel/btf/vmlinux ]; then echo "btf: yes ($(stat -c %s /sys/kernel/btf/vmlinux) bytes)"; else echo "btf: no"; fi
echo "cgroup mount: $(findmnt -n -o FSTYPE,OPTIONS /sys/fs/cgroup)"
echo "cgroup controllers: $(cat /sys/fs/cgroup/cgroup.controllers)"
echo "block tracepoints: $(ls /sys/kernel/tracing/events/block 2>&1 | tr '\n' ' ')"
echo "block_rq_issue format:"
grep -E '^(name|\s+field)' /sys/kernel/tracing/events/block/block_rq_issue/format 2>&1 | sed 's/^/  /'
echo "--- blkprobe ---"
cd blkprobe
start=$(date +%s.%N)
./blkprobe /tmp/disk.img
rc=$?
echo "blkprobe rc=$rc ($(awk -v a=$start -v b=$(date +%s.%N) 'BEGIN{printf "%.1f", b-a}')s)"
exit $rc
