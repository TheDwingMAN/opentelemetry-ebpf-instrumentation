#!/bin/bash
# dm-multipath as multipathd builds it for a SAN LUN: a request-based device mapper volume over two
# scsi_debug disks that share one store (two paths to one LUN), with a volatile write cache and FUA.
# Checks that OBI counts the reads, writes, bytes and flushes of the volume and of its paths as their
# own lines in /proc/diskstats do: device mapper completes the bytes of each request of the volume
# when its clone completes on a path, and ends the request again afterwards, without bytes.
set -u
echo "uname -r: $(uname -r)"
fail=0
step() { echo; echo "##### $*"; }
result() { if [ "$2" -eq 0 ]; then echo "RESULT $1 PASS"; else echo "RESULT $1 FAIL (rc=$2)"; fail=1; fi; }

step "dm-multipath over two scsi_debug paths"
modprobe sd_mod 2>/dev/null
if ! modprobe scsi_debug add_host=2 num_tgts=1 max_luns=1 dev_size_mb=64; then
  echo "SKIP dm-mpath scsi_debug can't be loaded"
  exit 0
fi
paths=""
for _ in $(seq 1 100); do
  paths=$(ls -d /sys/bus/pseudo/drivers/scsi_debug/adapter*/host*/target*/*/block/* 2>/dev/null | xargs -rn1 basename | sort | tr '\n' ' ')
  [ "$(echo $paths | wc -w)" -ge 2 ] && break
  sleep 0.1
done
set -- $paths
[ $# -ge 2 ] || { echo "SKIP dm-mpath scsi_debug created fewer than 2 disks"; exit 0; }
p1=$1 p2=$2
for p in $p1 $p2; do [ -b /dev/$p ] || mknod /dev/$p b $(tr ':' ' ' < /sys/class/block/$p/dev); done
if ! modprobe -a dm_multipath dm_round_robin; then
  echo "SKIP dm-mpath dm-multipath can't be loaded"
  exit 0
fi
sectors=$(cat /sys/class/block/$p1/size)
# no features: queue_mode is mq (request-based); round-robin switches path after each request
DM_DISABLE_UDEV=1 dmsetup create labmpath --table "0 $sectors multipath 0 0 1 1 round-robin 0 2 1 /dev/$p1 1 /dev/$p2 1"
result dm-mpath-setup $?
dm=$(dmsetup info -c --noheadings -o blkdevname labmpath | tr -d ' ')
[ -b /dev/$dm ] || mknod /dev/$dm b $(tr ':' ' ' < /sys/class/block/$dm/dev)
for d in $dm $p1 $p2; do
  echo "$d: mq=$([ -d /sys/block/$d/mq ] && echo yes || echo no) write_cache='$(cat /sys/block/$d/queue/write_cache)' fua=$(cat /sys/block/$d/queue/fua 2>/dev/null) slaves='$(ls /sys/block/$d/slaves | tr '\n' ' ')'"
done

OTEL_EBPF_METRICS_FEATURES=stats_disk OTEL_EBPF_PROMETHEUS_PORT=9400 \
OTEL_EBPF_BPF_BATCH_TIMEOUT=100ms OTEL_EBPF_HOSTNAME=lab OTEL_EBPF_STATS_AGENT_IP=10.0.2.15 \
  ./obi > "$LAB_RESULTS/obi.log" 2>&1 &
obi_pid=$!
up=0
for _ in $(seq 1 180); do
  if curl -sf localhost:9400/metrics >/dev/null 2>&1; then up=1; break; fi
  kill -0 $obi_pid 2>/dev/null || break
  sleep 1
done
[ $up -eq 1 ] || { echo "obi did not start"; tail -30 "$LAB_RESULTS/obi.log"; result dm-mpath-obi-running 1; exit 1; }
sleep 35 # past the 30 s device refresh, so the volume is labelled stacked

step "I/O on $dm: 64 direct writes, 1000 direct O_DSYNC writes, 500 direct reads"
curl -sf localhost:9400/metrics > "$LAB_RESULTS/before.txt"
cat /proc/diskstats > /tmp/ds0.txt
dd if=/dev/zero of=/dev/$dm bs=4k count=64 oflag=direct status=none
dd if=/dev/zero of=/dev/$dm bs=4k count=1000 oflag=direct,dsync status=none
dd if=/dev/$dm of=/dev/null bs=4k count=500 iflag=direct status=none
# device mapper ends a request after its bytes completed: wait until the kernel has counted them all
for _ in $(seq 1 50); do [ "$(cat /sys/block/$dm/inflight | tr -s ' ' | sed 's/^ //')" = "0 0" ] && break; sleep 0.1; done
cat /proc/diskstats > /tmp/ds1.txt
sleep 5
curl -sf localhost:9400/metrics > "$LAB_RESULTS/after.txt"
kill $obi_pid; wait $obi_pid 2>/dev/null

# ds <device> <field>: the change of a field of the device's line in /proc/diskstats (4 reads,
# 6 sectors read, 8 writes, 10 sectors written, 19 flushes)
ds() { echo $(( $(awk -v d="$1" -v f="$2" '$3 == d {print $f}' /tmp/ds1.txt) - $(awk -v d="$1" -v f="$2" '$3 == d {print $f}' /tmp/ds0.txt) )); }
# /proc/diskstats has the flush fields since Linux 5.5: RHEL 8 (4.18) has none
flush_fields=$(awk -v d="$dm" '$3 == d {print (NF >= 20 ? 1 : 0)}' /tmp/ds1.txt)
ds_flushes() { if [ "$flush_fields" = 1 ]; then ds "$1" 19; else echo none; fi; }
# obi <metric> <device> [direction]: the change of an OBI counter, summed over its series
obi_sum() { grep "^$2{" "$1" | grep -F "system_device=\"$3\"" | grep -F "${4:-}" | awk '{s += $NF} END {printf "%.0f", s}'; }
obi() { echo $(( $(obi_sum "$LAB_RESULTS/after.txt" "$@") - $(obi_sum "$LAB_RESULTS/before.txt" "$@") )); }
ops=obi_stat_disk_operations_total
bytes=obi_stat_disk_io_bytes_total
flushes=obi_stat_disk_flush_duration_seconds_count
for d in $dm $p1 $p2; do
  echo "$d diskstats: reads=$(ds $d 4) sectors_read=$(ds $d 6) writes=$(ds $d 8) sectors_written=$(ds $d 10) flushes=$(ds_flushes $d)"
  echo "$d obi: reads=$(obi $ops $d 'direction="read"') read_bytes=$(obi $bytes $d 'direction="read"') writes=$(obi $ops $d 'direction="write"') written_bytes=$(obi $bytes $d 'direction="write"') flushes=$(obi $flushes $d)"
done

[ "$(obi $ops $dm 'direction="write"')" -eq "$(ds $dm 8)" ]; result dm-mpath-volume-writes-match-diskstats $?
[ "$(obi $ops $dm 'direction="read"')" -eq "$(ds $dm 4)" ]; result dm-mpath-volume-reads-match-diskstats $?
[ "$(obi $bytes $dm 'direction="write"')" -eq $(( $(ds $dm 10) * 512 )) ]; result dm-mpath-volume-written-bytes-match-diskstats $?
[ "$(obi $bytes $dm 'direction="read"')" -eq $(( $(ds $dm 6) * 512 )) ]; result dm-mpath-volume-read-bytes-match-diskstats $?
if [ "$flush_fields" = 1 ]; then
  [ "$(obi $flushes $dm)" -eq "$(ds $dm 19)" ]; result dm-mpath-volume-flushes-match-diskstats $?
else
  echo "SKIP dm-mpath-volume-flushes-match-diskstats /proc/diskstats has no flush fields before Linux 5.5"
fi
stacked=$(grep "^$ops{" "$LAB_RESULTS/after.txt" | grep -F "system_device=\"$dm\"" | grep -vc 'obi_disk_stacked="true"')
[ "$stacked" -eq 0 ]; result dm-mpath-volume-stacked-label $?

pw=0 pr=0 pf=0 dw=0 dr=0 df=0
for p in $p1 $p2; do
  pw=$((pw + $(obi $ops $p 'direction="write"'))) pr=$((pr + $(obi $ops $p 'direction="read"'))) pf=$((pf + $(obi $flushes $p)))
  dw=$((dw + $(ds $p 8))) dr=$((dr + $(ds $p 4)))
  [ "$flush_fields" = 1 ] && df=$((df + $(ds $p 19)))
done
[ "$pw" -eq "$dw" ]; result dm-mpath-path-writes-match-diskstats $?
# the paths count the clones of the volume's cache flushes as reads in /proc/diskstats (a flush
# request outside a flush sequence is accounted with the reads), and no flush: OBI counts them as
# flushes (without the flush fields, RHEL 8 counts them as reads too)
[ $((pr + pf)) -eq "$dr" ] && [ "$df" -eq 0 ]; result dm-mpath-path-reads-and-flushes-match-diskstats $?
DM_DISABLE_UDEV=1 dmsetup remove labmpath
exit $fail
