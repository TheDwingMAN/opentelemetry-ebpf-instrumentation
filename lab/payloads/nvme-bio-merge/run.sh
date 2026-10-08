#!/bin/bash
# OBI's bio probes on an NVMe native multipath head when the paths merge (or the head splits) its
# bios. Run with LAB_NVME_MPATH=256M. The NVMe driver traces block_bio_complete on the head only for
# the first bio of each path request (nvme_trace_bio_complete), and blk_update_request keeps
# bio_endio from tracing the others, so OBI completes the head's bios when the path request completes
# (block_rq_complete in tp_bio.c). Phases: A the direct-I/O baseline of the nvme-mpath payloads
# (64 direct writes, 1000 direct O_DSYNC writes, 500 direct reads on the head), M mkfs.ext4 on the
# head, B 32 MiB of buffered sequential 4 KiB writes to a file and one fsync, C 1000 buffered 4 KiB
# files and a sync. After each phase: the head's and the paths' /proc/diskstats, OBI's head counters,
# and the entries of disk_bio_start (./bpfmaps: the bios OBI recorded at block_bio_queue and has not
# completed). Expected: the head's written bytes equal its /proc/diskstats in every phase; its writes
# count the bios submitted to the head, so they equal the head's line plus the paths' merges (A, M,
# C), and differ by definition when the head splits large bios into path requests (B); no entry is
# left in disk_bio_start.
set -u
echo "uname -r: $(uname -r)"
fail=0
step() { echo; echo "##### $*"; }
result() { if [ "$2" -eq 0 ]; then echo "RESULT $1 PASS"; else echo "RESULT $1 FAIL (rc=$2)"; fail=1; fi; }

step "nvme multipath"
modprobe nvme_core multipath=Y 2>/dev/null
modprobe nvme 2>/dev/null
for _ in $(seq 1 20); do ls /sys/block | grep -q '^nvme' && break; sleep 1; done
head=$(ls /sys/block | grep -E '^nvme[0-9]+n[0-9]+$' | head -1)
paths=$(ls /sys/block | grep -E '^nvme[0-9]+c[0-9]+n[0-9]+$' | tr '\n' ' ')
echo "head=$head paths=$paths"
if [ -z "$head" ] || [ "$(echo $paths | wc -w)" -lt 2 ]; then echo "SKIP nvme-bio-merge no multipath head with two paths"; exit 0; fi
[ -b /dev/$head ] || mknod /dev/$head b $(tr ':' ' ' < /sys/block/$head/dev)
q() { cat /sys/block/$1/queue/$2 2>/dev/null || echo n/a; }
for d in $head $paths; do
  echo "$d: max_sectors_kb=$(q $d max_sectors_kb) max_hw_sectors_kb=$(q $d max_hw_sectors_kb) nomerges=$(q $d nomerges) scheduler='$(q $d scheduler)' write_cache='$(q $d write_cache)' iostats=$(q $d iostats)"
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
[ $up -eq 1 ] || { echo "obi did not start"; tail -30 "$LAB_RESULTS/obi.log"; result nvme-bio-merge-obi-running 1; exit 1; }
sleep 35 # past the 30 s device refresh, so the head is in the bio device set

snap() { sync; sleep 5; cat /proc/diskstats > "$LAB_RESULTS/$1.ds"; curl -sf --max-time 30 localhost:9400/metrics > "$LAB_RESULTS/$1.prom"; ./bpfmaps disk_bio_start > "$LAB_RESULTS/$1.bio" 2>&1; }
# dsd <from> <to> <device> <field>: the change of a /proc/diskstats field (4 reads, 5 reads merged,
# 6 sectors read, 8 writes, 9 writes merged, 10 sectors written)
dsd() { echo $(( $(awk -v d="$3" -v f="$4" '$3 == d {print $f}' "$LAB_RESULTS/$2.ds") - $(awk -v d="$3" -v f="$4" '$3 == d {print $f}' "$LAB_RESULTS/$1.ds") )); }
psum() { local s=0; for p in $paths; do s=$((s + $(dsd $1 $2 $p $3))); done; echo $s; }
obi_sum() { grep "^$2{" "$LAB_RESULTS/$1.prom" | grep -F "system_device=\"$3\"" | grep -F "$4" | awk '{s += $NF} END {printf "%.0f", s}'; }
obid() { echo $(( $(obi_sum $2 "$3" "$4" "$5") - $(obi_sum $1 "$3" "$4" "$5") )); }
entries() { awk '$1 == "disk_bio_start" {s += $2} END {print s + 0}' "$LAB_RESULTS/$1.bio"; }
ops=obi_stat_disk_operations_total bytes=obi_stat_disk_io_bytes_total
report() { # report <from> <to> <phase>
  local hw hws ow ob hr hrs or orb pm
  hw=$(dsd $1 $2 $head 8) hws=$(dsd $1 $2 $head 10) hr=$(dsd $1 $2 $head 4) hrs=$(dsd $1 $2 $head 6) pm=$(psum $1 $2 9)
  ow=$(obid $1 $2 $ops $head 'direction="write"') ob=$(obid $1 $2 $bytes $head 'direction="write"')
  or=$(obid $1 $2 $ops $head 'direction="read"') orb=$(obid $1 $2 $bytes $head 'direction="read"')
  echo "$3 head $head diskstats: writes=$hw written_bytes=$((hws * 512)) reads=$hr read_bytes=$((hrs * 512)) (reads include one per cache flush)"
  echo "$3 head $head obi:       writes=$ow written_bytes=$ob reads=$or read_bytes=$orb"
  echo "$3 paths diskstats: writes=$(psum $1 $2 8) writes_merged=$(psum $1 $2 9) written_bytes=$(( $(psum $1 $2 10) * 512 )) reads=$(psum $1 $2 4) reads_merged=$(psum $1 $2 5)"
  echo "$3 disk_bio_start entries: $(entries $1) -> $(entries $2)"
  [ "$ob" -eq $((hws * 512)) ]; result $3-head-written-bytes-match-diskstats $?
  if [ "$3" = B ]; then
    echo "SKIP B-head-bios-are-requests-plus-merges the head splits each large bio into path requests: OBI counts the bio once, the head's line each part"
  else
    [ "$ow" -eq $((hw + pm)) ]; result $3-head-bios-are-requests-plus-merges $?
  fi
  [ "$(entries $2)" = 0 ]; result $3-no-bio-left-in-disk-bio-start $?
}

snap s0
echo "at start: disk_bio_start entries: $(entries s0)"

step "A: direct I/O baseline on $head"
timeout 300 dd if=/dev/zero of=/dev/$head bs=4k count=64 oflag=direct status=none
timeout 300 dd if=/dev/zero of=/dev/$head bs=4k count=1000 oflag=direct,dsync status=none
timeout 300 dd if=/dev/$head of=/dev/null bs=4k count=500 iflag=direct status=none
snap s1; report s0 s1 A

step "M: mkfs.ext4 on $head"
timeout 300 mkfs.ext4 -q -F -E nodiscard,lazy_itable_init=0,lazy_journal_init=0 /dev/$head
mkdir -p /mnt/nv && mount /dev/$head /mnt/nv
snap s2; report s1 s2 M

step "B: 32 MiB of buffered sequential 4 KiB writes and one fsync"
timeout 300 dd if=/dev/zero of=/mnt/nv/seq bs=4k count=8192 conv=fsync status=none
snap s3; report s2 s3 B

step "C: 1000 buffered 4 KiB files and a sync"
mkdir -p /mnt/nv/small
for i in $(seq 1 1000); do head -c 4096 /dev/zero > /mnt/nv/small/f$i; done
timeout 300 sync
snap s4; report s3 s4 C

umount /mnt/nv
snap s5
echo "after umount: disk_bio_start entries: $(entries s5)"
[ "$(entries s5)" = 0 ]; result no-bio-left-after-umount $?
kill $obi_pid; wait $obi_pid 2>/dev/null
exit $fail
