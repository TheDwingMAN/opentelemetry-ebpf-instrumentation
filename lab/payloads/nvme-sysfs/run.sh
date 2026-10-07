#!/bin/bash
# Where can userspace find the device number and the head of a hidden NVMe multipath path?
modprobe nvme_core multipath=Y 2>/dev/null; modprobe nvme 2>/dev/null
for _ in $(seq 1 20); do ls /sys/block | grep -q '^nvme' && break; sleep 1; done
for d in /sys/block/nvme*; do
  n=$(basename $d); echo "== $n -> $(readlink -f $d)"
  echo "  uevent: $(tr '\n' ' ' < $d/uevent 2>/dev/null)"
  echo "  dev: $(cat $d/dev 2>/dev/null || echo absent)  hidden: $(cat $d/hidden 2>/dev/null)"
  ls $d/multipath 2>/dev/null | sed 's/^/  multipath: /'
done
echo "== /sys/dev/block entries for major 259:"; ls -l /sys/dev/block | grep ' 259:' | sed 's/^/  /'
echo "== /proc/diskstats nvme lines:"; grep nvme /proc/diskstats | sed 's/^/  /'
echo "== /sys/class/block:"; ls /sys/class/block | grep nvme | sed 's/^/  /'
