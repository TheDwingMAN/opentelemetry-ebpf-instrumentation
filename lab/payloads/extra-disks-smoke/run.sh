#!/bin/bash
# Lists the virtio disks and their serials, to check LAB_EXTRA_DISKS.
for d in /sys/block/vd*; do echo "${d##*/} serial=$(cat $d/serial 2>/dev/null) sectors=$(cat $d/size)"; done
found=""
for d in /sys/block/vd*; do [ "$(cat $d/serial 2>/dev/null)" = lab-extra-1 ] && found=${d##*/}; done
[ -n "$found" ] && echo "RESULT extra-disk-by-serial PASS ($found)" || { echo "RESULT extra-disk-by-serial FAIL"; exit 1; }
