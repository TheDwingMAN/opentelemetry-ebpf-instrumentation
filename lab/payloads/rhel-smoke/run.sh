#!/bin/bash
echo "uname -r: $(uname -r)"
cat /etc/os-release | head -2
ls /sys/kernel/btf/ | head
grep -c . /proc/kallsyms
ls /sys/fs/cgroup/ | head -5
cat /sys/fs/cgroup/cgroup.controllers
for m in loop null_blk dm_mod raid0 nfs nfsd; do modprobe $m && echo "modprobe $m ok" || echo "modprobe $m FAIL"; done
ls /sys/kernel/btf/
echo hello > "$LAB_RESULTS/hello.txt"
