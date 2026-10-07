#!/bin/bash
# iostats payload: does v2 time a request from a stale rq->start_time_ns when the device has
# queue/iostats=0? Per device (loop, virtio extra disk, null_blk) and scheduler (none, mq-deadline):
#   A  iostats=1: requests are accounted, so the kernel stamps start_time_ns; the tags get used
#   B  iostats=0, after W seconds: the same tags are reused; stale if the kernel does not restamp
#   C  iostats=1 again: control that OBI times the same device correctly in this window
# plus D, null_blk with shared_tags=1: nullb0 (iostats=1) leaves stamps that nullb1 (iostats=0) reuses.
# A "reuse witness" (the tag bitmap word CPU 0 allocates from, read from debugfs) shows that B
# allocates from the word A walked through. All I/O runs on CPU 0.
set -u
export LC_ALL=C

N_A=${IOSTATS_N_A:-2048}         # direct 4k reads while accounted
N_B=${IOSTATS_N_B:-256}          # direct 4k reads in B and in C
K=${IOSTATS_K:-32}               # writes, each followed by an fsync (an empty PREFLUSH)
W=${IOSTATS_W:-8}                # seconds between A and B; above the 5 s top finite bucket
BUDGET=${IOSTATS_BUDGET:-570}    # no new combination starts when it could end after this (seconds)
HARD=${IOSTATS_HARD:-595}        # every wait ends before this (seconds)
PORT=9400
R=${LAB_RESULTS:-/tmp/iostats-results}
mkdir -p "$R"

fail=0
step() { echo; echo "##### $*"; }
info() { echo "INFO $*"; }
skip() { echo "SKIP $1 $2"; }
result() { # name rc
  if [ "$2" -eq 0 ]; then echo "RESULT $1 PASS"; else echo "RESULT $1 FAIL (rc=$2)"; fail=1; fi
}
flag_rc() { [ "$1" -eq 1 ] && echo 0 || echo 1; } # 1 -> rc 0, anything else -> rc 1
cmp() { # a op b, numerically
  awk -v a="$1" -v op="$2" -v b="$3" 'BEGIN {
    if (op == ">=") r = (a + 0 >= b + 0); else if (op == "<=") r = (a + 0 <= b + 0)
    else if (op == "==") r = (a + 0 == b + 0); else r = 0
    exit !r }'
}
mean() { awk -v s="$1" -v c="$2" 'BEGIN { printf "%.6f", (c > 0) ? s / c : 0 }'; }
qread() { cat "/sys/block/$1/queue/$2" 2>/dev/null || echo absent; }
queue_line() { # device
  echo "scheduler='$(qread "$1" scheduler)' write_cache='$(qread "$1" write_cache)'" \
    "nr_requests=$(qread "$1" nr_requests) iostats=$(qread "$1" iostats) wbt_lat_usec=$(qread "$1" wbt_lat_usec)"
}
ensure_node() { # device: make /dev/<device> exist
  local major minor
  [ -b "/dev/$1" ] && return 0
  IFS=: read -r major minor < "/sys/class/block/$1/dev"
  mknod "/dev/$1" b "$major" "$minor"
}

#### what the kernel looks like
echo "uname -r: $(uname -r)"
btf_hits=$(grep -c -a __RQF_IO_STAT /sys/kernel/btf/vmlinux 2>/dev/null)
info "btf __RQF_IO_STAT (grep -c -a /sys/kernel/btf/vmlinux): ${btf_hits:-no BTF}"
info "kallsyms queue_iostats_passthrough_show (1 expected only on 6.18 and 7.2): $(grep -c ' queue_iostats_passthrough_show$' /proc/kallsyms)"
for q in /sys/block/*/queue; do
  d=${q%/queue}; d=${d##*/}
  info "device $d $(queue_line "$d")"
done
mountpoint -q /sys/kernel/debug || mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null

mode=current # "fixed" if the payload holds a MODE file saying so, for a binary with the iostats gate
[ -f ./MODE ] && mode=$(tr -d ' \n' < ./MODE)
IFS=. read -r kmaj kmin _ <<< "$(uname -r)"
kmin=${kmin%%[!0-9]*}
expect=CLEAN
if [ "$kmaj" -gt 6 ] || { [ "$kmaj" -eq 6 ] && [ "$kmin" -ge 13 ]; }; then expect=STALE; fi
[ "$mode" = fixed ] && expect=CLEAN
info "mode=$mode expect=$expect (current binary: STALE from kernel 6.13, CLEAN before; fixed binary: CLEAN everywhere)"
info "commit: $(head -1 ./COMMIT 2>/dev/null)"

#### the devices, created before OBI starts as the other payloads do
LOOP_DEV=""
NULLB_DEV=""
VIRTIO_DEV=""
TOUCHED=()

nullb_remove() {
  [ -d /sys/kernel/config/nullb/iostats ] || return 0
  echo 0 > /sys/kernel/config/nullb/iostats/power 2>/dev/null
  rmdir /sys/kernel/config/nullb/iostats 2>/dev/null
}
# shellcheck disable=SC2329 # runs from the EXIT trap
cleanup() {
  local d
  for d in "${TOUCHED[@]}"; do echo 1 > "/sys/block/$d/queue/iostats" 2>/dev/null; done
  [ -n "${obi_pid:-}" ] && kill "$obi_pid" 2>/dev/null
  [ -n "$LOOP_DEV" ] && losetup -d "/dev/$LOOP_DEV" 2>/dev/null
  nullb_remove
}
trap cleanup EXIT

make_loop() {
  local lp
  truncate -s 256M /tmp/iostats-loop.img && lp=$(losetup -f --show /tmp/iostats-loop.img) || return 1
  LOOP_DEV=${lp#/dev/}
  ensure_node "$LOOP_DEV"
}
make_virtio() {
  local q
  for q in /sys/block/vd*; do
    [ "$(cat "$q/serial" 2>/dev/null)" = lab-extra-1 ] && VIRTIO_DEV=${q##*/}
  done
  [ -n "$VIRTIO_DEV" ] && ensure_node "$VIRTIO_DEV"
}
make_nullb() {
  local before cfg=/sys/kernel/config/nullb/iostats
  modprobe -r null_blk 2>/dev/null
  modprobe null_blk nr_devices=0 2>/dev/null || return 1
  mkdir -p "$cfg" || return 1
  echo 256 > "$cfg/size"
  echo 64 > "$cfg/hw_queue_depth"
  echo 1 > "$cfg/submit_queues"
  before=$(ls /sys/block)
  echo 1 > "$cfg/power" || return 1
  NULLB_DEV=$(comm -13 <(echo "$before") <(ls /sys/block) | head -1)
  [ -n "$NULLB_DEV" ] && ensure_node "$NULLB_DEV"
}

make_loop || skip device-loop "cannot create a loop device"
if make_virtio; then
  info "virtio extra disk lab-extra-1 is $VIRTIO_DEV"
else
  skip device-virtio "no virtio disk with serial lab-extra-1 (run with LAB_EXTRA_DISKS=\"1G\")"
fi
make_nullb || skip device-nullb "null_blk is not available (modprobe or configfs failed)"
[ -n "$LOOP_DEV" ] && info "loop device: $LOOP_DEV"
[ -n "$NULLB_DEV" ] && info "null_blk device: $NULLB_DEV"

#### OBI
cat > /tmp/obi.yml <<'YML'
attributes:
  select:
    obi.stat.disk.operations:
      include: ["*"]
    obi.stat.disk.operation.duration:
      include: ["*"]
    obi.stat.disk.operation.time:
      include: ["*"]
    obi.stat.disk.queue.duration:
      include: ["*"]
YML
[ -x ./obi ] || { echo "no ./obi"; result obi-start 1; exit 1; }
# the binary tells whether it has the iostats gate (disk_rqf_io_stat) or not
(
  echo "sha256 $(sha256sum ./obi | cut -d' ' -f1)"
  echo "disk_rqf_flush_seq $(grep -a -c disk_rqf_flush_seq ./obi)"
  echo "disk_rqf_io_stat $(grep -a -c disk_rqf_io_stat ./obi)"
) > "$R/binary.txt" 2>&1 &
binary_pid=$!
OTEL_EBPF_METRICS_FEATURES=stats_disk OTEL_EBPF_PROMETHEUS_PORT=$PORT \
OTEL_EBPF_BPF_BATCH_TIMEOUT=100ms OTEL_EBPF_LOG_LEVEL=debug OTEL_EBPF_HOSTNAME=lab OTEL_EBPF_STATS_AGENT_IP=10.0.2.15 \
  ./obi -config /tmp/obi.yml > "$R/obi.log" 2>&1 &
obi_pid=$!
up=0
for _ in $(seq 1 180); do
  if curl -sf localhost:$PORT/metrics >/dev/null 2>&1; then up=1; break; fi
  kill -0 $obi_pid 2>/dev/null || break
  sleep 1
done
[ $up -eq 1 ] || { echo "obi did not start"; tail -30 "$R/obi.log"; result obi-start 1; exit 1; }
sleep 3 # let the probes attach
wait $binary_pid
info "obi started after $SECONDS s; binary: $(tr '\n' ' ' < "$R/binary.txt")"
io_stat_hits=$(awk '$1 == "disk_rqf_io_stat" { print $2 }' "$R/binary.txt")
binary_ok=1
if [ "$mode" = fixed ]; then
  [ "${io_stat_hits:-0}" -gt 0 ] || binary_ok=0
else
  [ "${io_stat_hits:-1}" -eq 0 ] || binary_ok=0
fi
result binary-matches-mode "$(flag_rc $binary_ok)"

#### metrics: one "key value" file per snapshot and device, summed over the series
snapshot() { # out: the stats_disk lines of /metrics
  curl -sf --max-time 20 localhost:$PORT/metrics 2>/dev/null | grep '^obi_stat_disk_' > "$1" || true
}
extract_kv() { # device metrics-file
  awk -v dev="system_device=\"$1\"" '
    function label(labels, key,   t, p, s) {
      t = "," labels ","
      p = index(t, "," key "=\"")
      if (p == 0) return ""
      s = substr(t, p + length(key) + 3)
      return substr(s, 1, index(s, "\"") - 1)
    }
    {
      b = index($0, "{")
      if (b == 0) next
      name = substr($0, 1, b - 1)
      labels = substr($0, b + 1)
      labels = substr(labels, 1, index(labels, "}") - 1)
      if (index("," labels ",", "," dev ",") == 0) next
      dir = label(labels, "disk_io_direction")
      if (name == "obi_stat_disk_operations_total") key = "ops_" dir
      else if (name == "obi_stat_disk_operation_time_seconds_total") key = "ot_" dir
      else if (name == "obi_stat_disk_queue_duration_seconds_count") key = "qcnt_" dir
      else if (name == "obi_stat_disk_queue_duration_seconds_sum") key = "qsum_" dir
      else if (name == "obi_stat_disk_queue_duration_seconds_bucket") key = "qb_" dir "_" label(labels, "le")
      else if (name == "obi_stat_disk_operation_duration_seconds_count") key = "odcnt_" dir
      else if (name == "obi_stat_disk_operation_duration_seconds_sum") key = "odsum_" dir
      else if (name == "obi_stat_disk_operation_duration_seconds_bucket") key = "odb_" dir "_" label(labels, "le")
      else if (name == "obi_stat_disk_flush_duration_seconds_count") key = "flcnt_" dir
      else next
      total[key] += $NF
    }
    END { for (k in total) printf "%s %.12g\n", k, total[k] }' "$2" | sort
}
kv_delta() { # before-kv after-kv; the files may be empty
  awk -v before="$1" '
    BEGIN { while ((getline line < before) > 0) { split(line, f, " "); b[f[1]] = f[2] } close(before) }
    { seen[$1] = 1; printf "%s %.9g\n", $1, $2 - b[$1] }
    END { for (k in b) if (!(k in seen)) printf "%s %.9g\n", k, -b[k] }' "$2" | sort
}
kvi() { awk -v k="$2" '$1 == k { v = $2 } END { printf "%.0f", v + 0 }' "$1"; }
kvf() { awk -v k="$2" '$1 == k { v = $2 } END { printf "%.6f", v + 0 }' "$1"; }
top_bucket() { # delta-kv, prefix such as qb_read: the highest bucket that got observations
  awk -v p="$2_" '
    index($1, p) == 1 { n++; le[n] = substr($1, length(p) + 1); cum[n] = $2 + 0; x[n] = (le[n] == "+Inf") ? 1e300 : le[n] + 0 }
    END {
      for (i = 2; i <= n; i++) {
        for (j = i; j > 1 && x[j - 1] > x[j]; j--) {
          t = x[j]; x[j] = x[j - 1]; x[j - 1] = t
          t = le[j]; le[j] = le[j - 1]; le[j - 1] = t
          t = cum[j]; cum[j] = cum[j - 1]; cum[j - 1] = t
        }
      }
      prev = 0; best = ""
      for (i = 1; i <= n; i++) { if (cum[i] - prev > 0.5) { best = le[i]; got = cum[i] - prev } prev = cum[i] }
      if (best == "") print "none"; else printf "le=%s(%d)\n", best, got
    }' "$1"
}
kstat() { awk '{ print $1, $5 }' "/sys/block/$1/stat"; } # reads and writes completed, as the kernel counts them

have_time() { [ $((SECONDS + est)) -le "$BUDGET" ]; }
est=70 # seconds a combination needs: 1.25 times the longest so far, a guess before the first one
est_seen=0
sleep_until() { # epoch seconds
  local rem
  rem=$(awk -v a="$1" -v b="$(date +%s.%N)" 'BEGIN { r = a - b; printf "%.3f", (r > 0) ? r : 0 }')
  sleep "$rem"
}

settle() { # device out-base before-base wanted-reads: scrapes until the device's counters stopped moving
  local d=$1 out=$2 before=$3 want=$4 prev="" same=0 sig got t0=$SECONDS limit
  limit=$((HARD - SECONDS)); [ "$limit" -gt 60 ] && limit=60; [ "$limit" -lt 10 ] && limit=10
  while :; do
    snapshot "$out.txt"
    extract_kv "$d" "$out.txt" > "$out.kv"
    sig=$(awk '{ s += $2 } END { printf "%.6f", s }' "$out.kv")
    got=$(($(kvi "$out.kv" ops_read) - $(kvi "$before.kv" ops_read)))
    if [ "$sig" = "$prev" ] && [ "$got" -ge "$want" ]; then same=$((same + 1)); else same=0; fi
    prev=$sig
    if [ "$same" -ge 2 ]; then info "settled $d in $((SECONDS - t0)) s: reads +$got of $want wanted"; return 0; fi
    if [ $((SECONDS - t0)) -ge "$limit" ]; then info "NOT settled $d after $limit s: reads +$got of $want wanted"; return 1; fi
    sleep 2
  done
}

#### I/O and the reuse witness
phase_io() { # device reads with-fsync-writes label; pinned to CPU 0, children included
  local d=$1 n=$2 fl=$3 tag=$4
  taskset -c 0 timeout 120 dd if="/dev/$d" of=/dev/null bs=4k count="$n" iflag=direct status=none 2>> "$R/io-$tag.log" \
    || info "dd on $d ($tag) failed rc=$?"
  [ "$fl" -eq 1 ] || return 0
  taskset -c 0 timeout 120 fio --name=fs --filename="/dev/$d" --rw=write --bs=4k --size=$((4 * K))k \
    --direct=1 --fsync=1 --ioengine=psync --output="$R/fio-$tag.log" > /dev/null 2>&1 \
    || info "fio on $d ($tag) failed rc=$?"
}
find_hctx() { # device: the hardware queue whose CPUs include CPU 0
  local h cl
  for h in /sys/block/"$1"/mq/*/; do
    cl=$(tr -d ' ' < "${h}cpu_list" 2>/dev/null) || continue
    case ",$cl," in *,0,*) basename "$h"; return 0 ;; esac
  done
  return 1
}
witness_read() { # device scheduler hctx: "word hint bits_per_word" of CPU 0's tag allocation hint
  local f=/sys/kernel/debug/block/$1/hctx$3/tags
  [ "$2" = none ] || f=/sys/kernel/debug/block/$1/hctx$3/sched_tags
  [ -r "$f" ] || return 1
  awk '
    index($0, "bits_per_word=") == 1 && bpw == "" { bpw = substr($0, 15) + 0 }
    index($0, "alloc_hint={") == 1 && !have {
      s = substr($0, 13); n = index(s, ","); if (n == 0) n = index(s, "}")
      hint = substr(s, 1, n - 1) + 0; have = 1
    }
    END { if (bpw > 0 && have) printf "%d %d %d\n", int(hint / bpw), hint, bpw; else exit 1 }' "$f"
}

#### verdicts
SUMMARY=()
verdict() { # name observed expected prerequisites(ok|fail|na)
  local v
  if [ "$4" != ok ]; then v=INCONCLUSIVE
  elif [ "$2" = "$3" ]; then if [ "$3" = STALE ]; then v=REPRODUCED; else v=ABSENT; fi
  elif [ "$2" = MIXED ]; then v=UNEXPLAINED
  else v=CONTRADICTION; fi
  info "verdict $1: $v (observed $2, expected $3)"
  SUMMARY+=("$1 $v observed=$2 expected=$3")
}
skip_combo() { # device tag reason
  local n
  for n in positive control witness stale-queue stale-flush; do skip "$n-$1-$2" "$3"; done
}

# evaluate <device> <tag> <flush>: the checks of one combination, from the snapshots
# $R/<device>-<tag>-{A,B,C}.kv and the E_* values set by run_combo
evaluate() {
  local d=$1 tag=$2 fl=$3 base=$R/$1-$2 B C
  local b_ops_r b_ops_w b_qc_r b_qc_w b_qs_r b_qs_w b_inf_r b_inf_w b_mean_r b_mean_w b_od_inf_w b_ot_w
  local c_ops_r c_ops_w c_qc_r c_qc_w c_inf_r c_inf_w c_fast_r
  local pos=0 ctl=0 wit=0 wit_na=0 pre obs_q obs_f w1 w2 w3
  kv_delta "$base-A.kv" "$base-B.kv" > "$base-dB.kv"
  kv_delta "$base-B.kv" "$base-C.kv" > "$base-dC.kv"
  B=$base-dB.kv; C=$base-dC.kv

  b_ops_r=$(kvi "$B" ops_read); b_ops_w=$(kvi "$B" ops_write)
  b_qc_r=$(kvi "$B" qcnt_read); b_qc_w=$(kvi "$B" qcnt_write)
  b_qs_r=$(kvf "$B" qsum_read); b_qs_w=$(kvf "$B" qsum_write)
  b_inf_r=$(($(kvi "$B" qcnt_read) - $(kvi "$B" qb_read_5)))
  b_inf_w=$(($(kvi "$B" qcnt_write) - $(kvi "$B" qb_write_5)))
  b_mean_r=$(mean "$b_qs_r" "$b_qc_r"); b_mean_w=$(mean "$b_qs_w" "$b_qc_w")
  b_od_inf_w=$(($(kvi "$B" odcnt_write) - $(kvi "$B" odb_write_5)))
  b_ot_w=$(kvf "$B" ot_write)
  c_ops_r=$(kvi "$C" ops_read); c_ops_w=$(kvi "$C" ops_write)
  c_qc_r=$(kvi "$C" qcnt_read); c_qc_w=$(kvi "$C" qcnt_write)
  c_inf_r=$(($(kvi "$C" qcnt_read) - $(kvi "$C" qb_read_5)))
  c_inf_w=$(($(kvi "$C" qcnt_write) - $(kvi "$C" qb_write_5)))
  c_fast_r=$(kvi "$C" qb_read_0.1)

  info "$d-$tag B (iostats=0, ${E_DT} s after A): ops_r=$b_ops_r ops_w=$b_ops_w kernel_reads=$E_KBR kernel_writes=$E_KBW"
  info "$d-$tag B queue duration: reads count=$b_qc_r over5s=$b_inf_r mean=$b_mean_r top=$(top_bucket "$B" qb_read);" \
    "writes count=$b_qc_w over5s=$b_inf_w mean=$b_mean_w top=$(top_bucket "$B" qb_write)"
  info "$d-$tag B writes: operation_duration over5s=$b_od_inf_w operation_time=$b_ot_w s flush_duration count=$(kvi "$B" flcnt_)"
  info "$d-$tag C (iostats=1): ops_r=$c_ops_r ops_w=$c_ops_w kernel_reads=$E_KCR kernel_writes=$E_KCW;" \
    "queue duration reads count=$c_qc_r over5s=$c_inf_r le0.1s=$c_fast_r top=$(top_bucket "$C" qb_read), writes count=$c_qc_w over5s=$c_inf_w"

  # positive: OBI saw the I/O of B (the reads, and the writes where the flushes are checked), and the kernel did not account it
  if cmp "$b_ops_r" '>=' "$N_B" && [ "$E_KBR" -eq 0 ] && [ "$E_KBW" -eq 0 ]; then pos=1; fi
  if [ "$fl" -eq 1 ] && ! cmp "$b_ops_w" '>=' "$K"; then pos=0; fi
  info "positive-$d-$tag: ops_r=$b_ops_r (want >= $N_B)$([ "$fl" -eq 1 ] && echo " ops_w=$b_ops_w (want >= $K)")," \
    "kernel deltas reads=$E_KBR writes=$E_KBW (want 0)"
  result "positive-$d-$tag" "$(flag_rc $pos)"

  # control: the same device is timed correctly while accounted
  if cmp "$c_qc_r" '>=' "$N_B" && [ "$c_inf_r" -eq 0 ] && [ "$c_inf_w" -eq 0 ] &&
     awk -v f="$c_fast_r" -v c="$c_qc_r" 'BEGIN { exit !(f >= 0.98 * c) }'; then ctl=1; fi
  if [ "$fl" -eq 1 ] && [ "$c_ops_w" -ne "$E_KCW" ]; then ctl=0; fi
  info "control-$d-$tag: q_cnt_r=$c_qc_r (want >= $N_B) q_inf_r=$c_inf_r q_inf_w=$c_inf_w (want 0) q_fast_r=$c_fast_r (want >= 0.98 q_cnt_r)" \
    "$([ "$fl" -eq 1 ] && echo "ops_w=$c_ops_w kernel_writes=$E_KCW (want equal)")"
  result "control-$d-$tag" "$(flag_rc $ctl)"

  # witness: the allocation hint stayed in the same bitmap word, so B reuses tags A walked through
  w1=${E_W1%% *}; w2=${E_W2%% *}; w3=${E_W3%% *}
  if [ -z "$E_W1" ] || [ -z "$E_W2" ] || [ -z "$E_W3" ]; then
    wit_na=1
    skip "witness-$d-$tag" "no tag bitmap in debugfs for CPU 0's hardware queue (hctx='${E_HCTX}'; dumps: '$E_W1' | '$E_W2' | '$E_W3')"
  else
    [ "$w1" = "$w2" ] && [ "$w2" = "$w3" ] && wit=1
    info "witness-$d-$tag: word/hint/bits_per_word before A: $E_W1, after A: $E_W2, after B: $E_W3 (hctx$E_HCTX)"
    result "witness-$d-$tag" "$(flag_rc $wit)"
  fi

  # what B shows
  obs_q=MIXED
  if cmp "$b_inf_r" '>=' "$((N_B / 2))" && cmp "$b_mean_r" '>=' "$((W - 1))"; then obs_q=STALE
  elif [ "$b_inf_r" -eq 0 ] && [ "$b_inf_w" -eq 0 ]; then obs_q=CLEAN; fi
  pre=ok
  if [ "$pos" -ne 1 ] || [ "$ctl" -ne 1 ] || [ "$wit" -ne 1 ]; then pre=fail; fi
  [ "$wit_na" -eq 1 ] && [ "$pos" -eq 1 ] && [ "$ctl" -eq 1 ] && pre=na
  info "stale-queue-$d-$tag: observed=$obs_q expect=$expect q_inf_r=$b_inf_r (STALE needs >= $((N_B / 2))) q_mean_r=$b_mean_r (STALE needs >= $((W - 1)))"
  if [ "$pre" = na ]; then
    skip "stale-queue-$d-$tag" "witness unavailable, INCONCLUSIVE (observed $obs_q, expected $expect)"
  else
    [ "$obs_q" = "$expect" ] && [ "$pre" = ok ]; result "stale-queue-$d-$tag" $?
  fi
  verdict "queue $d-$tag" "$obs_q" "$expect" "$pre"

  if [ "$fl" -eq 1 ]; then
    obs_f=MIXED
    if cmp "$b_od_inf_w" '>=' "$((K / 2))" && cmp "$b_ot_w" '>=' "$((K * (W - 1)))"; then obs_f=STALE
    elif [ "$b_od_inf_w" -eq 0 ]; then obs_f=CLEAN; fi
    info "stale-flush-$d-$tag: observed=$obs_f expect=$expect od_inf_w=$b_od_inf_w (STALE needs >= $((K / 2))) ot_w=$b_ot_w (STALE needs >= $((K * (W - 1)))) ops_w=$b_ops_w"
    if [ "$pre" = na ]; then
      skip "stale-flush-$d-$tag" "witness unavailable, INCONCLUSIVE (observed $obs_f, expected $expect)"
    else
      [ "$obs_f" = "$expect" ] && [ "$pre" = ok ]; result "stale-flush-$d-$tag" $?
    fi
    verdict "flush $d-$tag" "$obs_f" "$expect" "$pre"
  else
    skip "stale-flush-$d-$tag" "write cache is '$(qread "$d" write_cache)', not 'write back': no flushes"
  fi
}

# run_combo <label> <device> <tag> <scheduler> <device of phase A>
run_combo() {
  local label=$1 d=$2 tag=$3 s=$4 a_dev=$5 q=/sys/block/$2/queue base=$R/$2-$3 t0=$SECONDS tA tB
  local kb0r kb0w kb1r kb1w kc0r kc0w kc1r kc1w
  step "$label: $d, scheduler $s, tag $tag"
  if ! have_time; then skip_combo "$d" "$tag" "time budget: $SECONDS s used, a combination needs up to $est s, the budget is $BUDGET s"; return; fi
  echo "$s" > "$q/scheduler" 2>/dev/null
  if ! grep -qF "[$s]" "$q/scheduler" 2>/dev/null; then
    skip_combo "$d" "$tag" "cannot select scheduler $s (queue/scheduler: $(qread "$d" scheduler))"; return
  fi
  TOUCHED+=("$d" "$a_dev")
  E_FLUSH=0; [ "$(qread "$d" write_cache)" = "write back" ] && E_FLUSH=1
  E_HCTX=$(find_hctx "$d") || E_HCTX=""
  info "$d $tag: $(queue_line "$d")"

  # A: accounted
  echo 1 > "$q/iostats"; echo 1 > "/sys/block/$a_dev/queue/iostats"
  E_W1=$(witness_read "$d" "$s" "$E_HCTX")
  snapshot "$base-0.txt"; extract_kv "$d" "$base-0.txt" > "$base-0.kv"
  phase_io "$a_dev" "$N_A" "$E_FLUSH" "$d-$tag-A"
  tA=$(date +%s.%N)
  settle "$d" "$base-A" "$base-0" "$([ "$a_dev" = "$d" ] && echo "$N_A" || echo 0)"
  E_W2=$(witness_read "$d" "$s" "$E_HCTX")

  # B: not accounted, W seconds later
  echo 0 > "$q/iostats"
  if [ "$(qread "$d" iostats)" != 0 ]; then
    skip_combo "$d" "$tag" "cannot set queue/iostats to 0 (reads back '$(qread "$d" iostats)')"; return
  fi
  sleep_until "$(awk -v t="$tA" -v w="$W" 'BEGIN { printf "%.3f", t + w }')"
  read -r kb0r kb0w < <(kstat "$d")
  tB=$(date +%s.%N)
  E_DT=$(awk -v a="$tA" -v b="$tB" 'BEGIN { printf "%.1f", b - a }')
  phase_io "$d" "$N_B" "$E_FLUSH" "$d-$tag-B"
  read -r kb1r kb1w < <(kstat "$d")
  settle "$d" "$base-B" "$base-A" "$N_B"
  E_W3=$(witness_read "$d" "$s" "$E_HCTX")

  # C: accounted again
  [ "$a_dev" = "$d" ] && sleep "$W"
  echo 1 > "$q/iostats"
  read -r kc0r kc0w < <(kstat "$d")
  phase_io "$d" "$N_B" "$E_FLUSH" "$d-$tag-C"
  read -r kc1r kc1w < <(kstat "$d")
  settle "$d" "$base-C" "$base-B" "$N_B"

  E_KBR=$((kb1r - kb0r)); E_KBW=$((kb1w - kb0w)); E_KCR=$((kc1r - kc0r)); E_KCW=$((kc1w - kc0w))
  evaluate "$d" "$tag" "$E_FLUSH"
  [ $((SECONDS - t0)) -gt "$est_seen" ] && est_seen=$((SECONDS - t0))
  est=$((est_seen + est_seen / 4))
  info "$d $tag took $((SECONDS - t0)) s; elapsed $SECONDS s"
}

#### the combinations
for entry in "loop:$LOOP_DEV" "virtio:$VIRTIO_DEV" "nullb:$NULLB_DEV"; do
  label=${entry%%:*}; dev=${entry#*:}
  [ -n "$dev" ] || continue
  for sched in none mq-deadline; do
    run_combo "$label" "$dev" "$sched" "$sched" "$dev"
  done
done

#### D: null_blk with shared tags: another disk's accounted use leaves the stamps nullb1 reuses
step "shared tags: nullb0 accounted, then nullb1 not"
if ! have_time; then
  skip_combo nullb1 shared "time budget: $SECONDS s used, a combination needs up to $est s, the budget is $BUDGET s"
else
  nullb_remove
  if modprobe -r null_blk 2>/dev/null && modprobe null_blk nr_devices=2 shared_tags=1 hw_queue_depth=64 submit_queues=1 gb=1 2>/dev/null \
     && [ -d /sys/block/nullb0 ] && [ -d /sys/block/nullb1 ]; then
    ensure_node nullb0; ensure_node nullb1
    echo none > /sys/block/nullb0/queue/scheduler 2>/dev/null
    run_combo shared nullb1 shared none nullb0
  else
    skip_combo nullb1 shared "null_blk with nr_devices=2 shared_tags=1 is not available"
  fi
fi

#### the end
curl -sf localhost:$PORT/metrics > "$R/metrics.txt"
kill $obi_pid; wait $obi_pid 2>/dev/null
step "summary"
for line in "${SUMMARY[@]}"; do info "summary $line"; done
info "RQF_FLUSH_SEQ lines in obi.log: $(grep -c RQF_FLUSH_SEQ "$R/obi.log")"
grep -iE 'level=(WARN|ERROR)' "$R/obi.log" | grep -iv 'imds\|kube\|cloud' | head -10
info "done in $SECONDS s"
exit $fail
