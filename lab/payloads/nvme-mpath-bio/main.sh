#!/bin/bash
# NVMe native multipath (audit item A8 on G4, d96357290): a shared namespace behind two
# controllers gives a bio-based head (nvmeXnY) over two hidden request-based paths. Checks
# that the head's bios are measured and complete (no stuck in-flight bios), that the head is
# labelled stacked, and that the paths carry the request metrics. Run with LAB_NVME_MPATH=256M.
set -u
echo "uname -r: $(uname -r)"
fail=0
step() { echo; echo "##### $*"; }
result() { if [ "$2" -eq 0 ]; then echo "RESULT $1 PASS"; else echo "RESULT $1 FAIL (rc=$2)"; fail=1; fi; }

step "nvme multipath"
modprobe nvme_core multipath=Y 2>/dev/null
modprobe nvme 2>/dev/null
echo "nvme_core multipath=$(cat /sys/module/nvme_core/parameters/multipath 2>/dev/null || echo n/a)"
for _ in $(seq 1 20); do ls /sys/block | grep -q '^nvme' && break; sleep 1; done
head=""
for d in /sys/block/nvme*; do
  [ -e "$d" ] || continue
  n=$(basename "$d")
  echo "$n: dev=$(cat $d/dev) scheduler='$(cat $d/queue/scheduler 2>/dev/null || echo absent)' mq=$([ -d $d/mq ] && echo yes || echo no) slaves='$(ls $d/slaves 2>/dev/null | tr '\n' ' ')' hidden=$(cat $d/hidden 2>/dev/null || echo n/a)"
  case $n in nvme*c*n*) ;; *) head=$n ;; esac
done
# the paths are hidden disks without a device number: /sys/block/nvmeXcYnZ with hidden=1
paths=$(ls -d /sys/block/nvme*c*n* 2>/dev/null | wc -l)
if [ -z "$head" ] || [ "$paths" -lt 2 ]; then
  echo "SKIP nvme-mpath no multipath head with two paths on this kernel (head='$head', paths=$paths)"
  exit 0
fi
[ -b /dev/$head ] || mknod /dev/$head b $(tr ':' ' ' < /sys/block/$head/dev)
echo "head $head with $paths paths"
# the kernel's hung-task detector prints the stack of any task blocked over 20 s; a watcher copies
# those reports to the output so a stuck I/O shows where it waits
echo 20 > /proc/sys/kernel/hung_task_timeout_secs 2>/dev/null
dmesg -c > /dev/null 2>&1
( while sleep 10; do dmesg -c 2>/dev/null | grep -A40 -E 'blocked for more than|INFO: task|Call Trace' | cut -c1-170; done ) &
watcher=$!
echo "obi features: ${NVME_OBI_FEATURES:=stats_disk}"

# control: the same I/O without OBI, so a hang of the emulated device is not blamed on OBI
io_ok() { # label, then the dd arguments
  local label=$1; shift
  if timeout 60 dd "$@" status=none; then echo "$label: ok"; return 0; fi
  echo "$label: dd did not finish in 60 s (rc=$?)"; dmesg | tail -25; return 1
}
# ds_guard <file> <label>: reads /proc/diskstats with a time limit; a stall is a kernel problem, so
# it dumps the reader's kernel stack and the kernel's blocked-task report
ds_guard() {
  cat /proc/diskstats > "$1" & local pid=$!
  for _ in $(seq 1 40); do kill -0 $pid 2>/dev/null || { wait $pid; echo "$2: diskstats read ok"; return 0; }; sleep 0.5; done
  echo "$2: /proc/diskstats read STALLED for 20 s (reader pid $pid, state $(awk '/^State/ {print $2}' /proc/$pid/status 2>/dev/null))"
  echo "--- reader kernel stack"; cat /proc/$pid/stack 2>/dev/null | head -20
  echo "--- blocked tasks (sysrq w)"; echo w > /proc/sysrq-trigger 2>/dev/null; sleep 1; dmesg | tail -60 | cut -c1-180
  return 1
}
io_ok "control write without obi" if=/dev/zero of=/dev/$head bs=4k count=64 oflag=direct
io_ok "control dsync write without obi" if=/dev/zero of=/dev/$head bs=4k count=1000 oflag=direct,dsync & bg=$!
io_ok "control read without obi" if=/dev/$head of=/dev/null bs=4k count=500 iflag=direct
wait $bg
ds_guard /tmp/ds-control.txt "control (same I/O pattern, no obi)"; result nvme-diskstats-without-obi $?

cat > /tmp/obi.yml <<'YML'
attributes:
  select:
    obi.stat.disk.operations:
      include: ["*"]
YML
OTEL_EBPF_METRICS_FEATURES=$NVME_OBI_FEATURES OTEL_EBPF_PROMETHEUS_PORT=9400 \
OTEL_EBPF_BPF_BATCH_TIMEOUT=100ms OTEL_EBPF_LOG_LEVEL=debug OTEL_EBPF_HOSTNAME=lab OTEL_EBPF_STATS_AGENT_IP=10.0.2.15 \
  ./obi -config /tmp/obi.yml > "$LAB_RESULTS/obi.log" 2>&1 &
obi_pid=$!
up=0
for _ in $(seq 1 180); do
  if curl -sf localhost:9400/metrics >/dev/null 2>&1; then up=1; break; fi
  kill -0 $obi_pid 2>/dev/null || break
  sleep 1
done
[ $up -eq 1 ] || { echo "obi did not start"; tail -30 "$LAB_RESULTS/obi.log"; result nvme-obi-running 1; exit 1; }
sleep 35 # past the 30 s device refresh, so the head is in the bio device set

sum() { # file metric filters...
  local file=$1 metric=$2; shift 2
  local lines; lines=$(grep "^${metric}{" "$file")
  for f in "$@"; do lines=$(echo "$lines" | grep -F "$f"); done
  echo "$lines" | awk 'NF {s+=$2} END {printf "%d", s}'
}
ds_writes() { awk -v d="$head" '$3 == d {print $8}' "$1"; }

curl -sf localhost:9400/metrics > "$LAB_RESULTS/before.txt"
ds_guard /tmp/ds-w0.txt "before the I/O with obi" || { result nvme-diskstats-with-obi-idle 1; exit 1; }
w0=$(ds_writes /tmp/ds-w0.txt)
io_ok "write with obi" if=/dev/zero of=/dev/$head bs=4k count=64 oflag=direct; result nvme-io-with-obi $?
io_ok "dsync write with obi" if=/dev/zero of=/dev/$head bs=4k count=1000 oflag=direct,dsync & bg=$!
io_ok "read with obi" if=/dev/$head of=/dev/null bs=4k count=500 iflag=direct
wait $bg
ds_guard /tmp/ds-w1.txt "after the I/O with obi"; result nvme-diskstats-after-io-with-obi $? || { kill -QUIT $obi_pid; sleep 2; grep -c "^goroutine" "$LAB_RESULTS/obi.log"; exit 1; }
w1=$(ds_writes /tmp/ds-w1.txt)
sleep 5
scrape() { # file: a scrape with a time limit; on a hang, dump obi's goroutines and kernel stacks
  if curl -sf --max-time 30 localhost:9400/metrics > "$1"; then echo "scrape $(basename $1): ok ($(wc -l < $1) lines)"; return 0; fi
  echo "scrape $(basename $1): HUNG or failed (rc=$?)"
  echo "--- kernel stacks of obi threads (blocked in the kernel?)"
  for t in /proc/$obi_pid/task/*; do st=$(cat $t/stack 2>/dev/null | head -8 | tr '\n' ' '); [ -n "$st" ] && echo "$(basename $t) $(cat $t/comm 2>/dev/null): $st"; done | grep -vE 'futex|epoll|ep_poll|do_nanosleep' | head -20
  echo "--- goroutine dump (SIGQUIT) goes to obi.log"
  kill -QUIT $obi_pid; sleep 3
  grep -nE '^goroutine|^\s+/home|^\s+go\.opentelemetry|^\s+github\.com|^\s+syscall|^\s+os\.|^\s+internal/poll' "$LAB_RESULTS/obi.log" | grep -vE 'select|chan receive|IO wait|sleep|runtime\.gopark|sigNoteSleep' | head -80 > "$LAB_RESULTS/goroutines.txt"
  echo "goroutines not waiting on select/chan/sleep: $(grep -cE '^[0-9]+:goroutine' "$LAB_RESULTS/goroutines.txt")"; head -60 "$LAB_RESULTS/goroutines.txt"
  result nvme-scrape-$(basename $1 .txt) 1
  return 1
}
scrape "$LAB_RESULTS/after.txt" || { fail=1; exit 1; }
sleep 10
scrape "$LAB_RESULTS/idle.txt" || { fail=1; exit 1; }
kill $obi_pid; wait $obi_pid 2>/dev/null

echo "devices in the metrics:"; grep -o 'system_device="[^"]*"' "$LAB_RESULTS/after.txt" | sort | uniq -c
grep -E "^obi_stat_disk_(operations_total|pending_operations)\{" "$LAB_RESULTS/after.txt" | grep -F nvme | head -20

hw=$(( $(sum "$LAB_RESULTS/after.txt" obi_stat_disk_operations_total "system_device=\"$head\"" 'disk_io_direction="write"') - $(sum "$LAB_RESULTS/before.txt" obi_stat_disk_operations_total "system_device=\"$head\"" 'disk_io_direction="write"') ))
echo "head $head: writes measured=$hw diskstats=$((w1 - w0)) (dd issued 1064)"
[ "$hw" -ge 1064 ]; result nvme-head-bio-writes $?
[ "$hw" -eq $((w1 - w0)) ]; result nvme-head-diskstats-match $?

stacked=$(grep -F "system_device=\"$head\"" "$LAB_RESULTS/after.txt" | grep -c 'obi_disk_stacked="true"')
echo "head series with obi_disk_stacked=true: $stacked"
[ "$stacked" -gt 0 ]; result nvme-head-stacked-label $?

pw=0
for p in $(ls -d /sys/block/nvme*c*n* | xargs -n1 basename); do
  d=$(( $(sum "$LAB_RESULTS/after.txt" obi_stat_disk_operations_total "system_device=\"$p\"" 'disk_io_direction="write"') - $(sum "$LAB_RESULTS/before.txt" obi_stat_disk_operations_total "system_device=\"$p\"" 'disk_io_direction="write"') ))
  echo "path $p: request writes=$d"
  pw=$((pw + d))
done
unstacked=$(grep '^obi_stat_disk_operations_total{' "$LAB_RESULTS/after.txt" | grep 'obi_disk_stacked="false"' | grep -F 'disk_io_direction="write"' | grep -vF "system_device=\"$head\"" | grep -F nvme | awk '{s+=$2} END {printf "%d", s}')
echo "request writes on the paths (by name)=$pw, unstacked nvme write series total=$unstacked"
[ "$pw" -ge 1064 ] || [ "$unstacked" -ge 1064 ]; result nvme-path-request-writes $?

pend=$(sum "$LAB_RESULTS/idle.txt" obi_stat_disk_pending_operations "system_device=\"$head\"")
echo "head pending operations after 10 s idle: $pend"
[ "$pend" -eq 0 ]; result nvme-no-stuck-pending $?

grep -iE 'level=(WARN|ERROR)' "$LAB_RESULTS/obi.log" | head -10
kill $watcher 2>/dev/null
exit $fail
