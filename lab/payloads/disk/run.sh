#!/bin/bash
# Chunk 1 kernel matrix payload: verifier, privileged loop-device test, obi end to end on null_blk.
set -u
echo "uname -r: $(uname -r)"
fail=0
step() { echo; echo "##### $*"; }
result() { # name rc
  if [ "$2" -eq 0 ]; then echo "RESULT $1 PASS"; else echo "RESULT $1 FAIL (rc=$2)"; fail=1; fi
}

step "BPF verifier (statsolly)"
./verifier.test -test.run 'TestBPFVerifierWithConstants/statsolly' -test.timeout 30m > "$LAB_RESULTS/verifier.log" 2>&1
rc=$?; tail -3 "$LAB_RESULTS/verifier.log"; result verifier $rc

step "privileged loop-device test"
./stats.test -test.v -test.run 'TestDiskLatencyIsAccumulatedPerDevice|TestDiskIOIsChargedPerCgroup|TestFsSyncIsChargedPerCgroup' -test.timeout 10m > "$LAB_RESULTS/privileged.log" 2>&1
rc=$?; grep -E '^(---|===|ok|FAIL|PASS)|Error' "$LAB_RESULTS/privileged.log" | head -20; result privileged-loop $rc

step "obi end to end on null_blk"
# a healthy device and one whose every sector is bad, so that its requests fail with BLK_STS_IOERR
modprobe -r null_blk 2>/dev/null
modprobe null_blk nr_devices=0 || { echo "no null_blk"; result e2e 1; exit 1; }
mkdir -p /sys/kernel/config/nullb/ok /sys/kernel/config/nullb/bad
for d in ok bad; do echo 64 > /sys/kernel/config/nullb/$d/size; done
echo "+0-511" > /sys/kernel/config/nullb/bad/badblocks || echo "setting badblocks failed"
echo "badblocks: $(head -c 200 /sys/kernel/config/nullb/bad/badblocks | tr '\n' ' ')"
# null_blk names configfs devices nullb<index> on older kernels and after the configfs directory on
# newer ones: take whichever block device appears when each one is powered on
power_on() {
  local before; before=$(ls /sys/block)
  echo 1 > /sys/kernel/config/nullb/$1/power
  comm -13 <(echo "$before") <(ls /sys/block) | head -1
}
ok_dev=$(power_on ok); bad_dev=$(power_on bad)
ls -l /dev/$ok_dev /dev/$bad_dev

OTEL_EBPF_METRICS_FEATURES=stats_disk,stats_fs_sync_duration OTEL_EBPF_PROMETHEUS_PORT=9400 \
OTEL_EBPF_BPF_BATCH_TIMEOUT=100ms OTEL_EBPF_LOG_LEVEL=debug OTEL_EBPF_HOSTNAME=lab OTEL_EBPF_STATS_AGENT_IP=10.0.2.15 \
  ./obi > "$LAB_RESULTS/obi.log" 2>&1 &
obi_pid=$!
up=0
for _ in $(seq 1 180); do
  if curl -sf localhost:9400/metrics >/dev/null 2>&1; then up=1; break; fi
  kill -0 $obi_pid 2>/dev/null || break
  sleep 1
done
[ $up -eq 1 ] || { echo "obi did not start"; tail -30 "$LAB_RESULTS/obi.log"; result e2e 1; exit 1; }
sleep 3 # let the probes attach

dd if=/dev/zero of=/dev/$ok_dev bs=4k count=200 oflag=direct status=none
for _ in $(seq 1 20); do dd if=/dev/zero of=/tmp/synced bs=4k count=1 conv=fsync status=none; done
dd if=/dev/$ok_dev of=/dev/null bs=4k count=300 iflag=direct status=none
dd if=/dev/$bad_dev of=/dev/null bs=4k count=5 iflag=direct conv=noerror status=none 2>"$LAB_RESULTS/dd-bad.log"
echo "dd on the bad device: $(grep -c 'Input/output error' "$LAB_RESULTS/dd-bad.log") I/O errors"
sleep 3
curl -sf localhost:9400/metrics > "$LAB_RESULTS/metrics.txt"
kill $obi_pid; wait $obi_pid 2>/dev/null

grep '^obi_stat_disk' "$LAB_RESULTS/metrics.txt" | grep '_count' 
count() { # device direction error_type [metric]
  grep "^${4:-obi_stat_disk_operation_duration_seconds_count}{" "$LAB_RESULTS/metrics.txt" \
    | grep "disk_io_direction=\"$2\"" | grep "system_device=\"$1\"" | grep "error_type=\"$3\"" \
    | awk '{s+=$2} END {print s+0}'
}
writes=$(count "$ok_dev" write ""); reads=$(count "$ok_dev" read ""); eio=$(count "$bad_dev" read EIO)
echo "histogram: writes=$writes (want 200) reads=$reads (want 300) EIO reads=$eio (want >=1)"
[ "$writes" = 200 ] && [ "$reads" = 300 ] && [ "$eio" -ge 1 ]
result e2e-histogram $?
ops_w=$(count "$ok_dev" write "" obi_stat_disk_operations_total); ops_r=$(count "$ok_dev" read "" obi_stat_disk_operations_total)
ops_eio=$(count "$bad_dev" read EIO obi_stat_disk_operations_total)
bytes_w=$(grep "^obi_stat_disk_io_bytes_total{" "$LAB_RESULTS/metrics.txt" | grep "system_device=\"$ok_dev\"" | grep 'disk_io_direction="write"' | awk '{s+=$2} END {printf "%d", s}')
# the bad device serves the reads after its bad range: only those transfer bytes
bytes_bad=$(grep "^obi_stat_disk_io_bytes_total{" "$LAB_RESULTS/metrics.txt" | grep "system_device=\"$bad_dev\"" | awk '{s+=$2} END {printf "%d", s}')
ok_reads_bad=$(count "$bad_dev" read "" obi_stat_disk_operations_total)
echo "counters: write ops=$ops_w (want 200) read ops=$ops_r (want 300) EIO ops=$ops_eio (want =histogram $eio) write bytes=$bytes_w (want 819200) bad device bytes=$bytes_bad (want $((ok_reads_bad * 4096)))"
[ "$ops_w" = 200 ] && [ "$ops_r" = 300 ] && [ "$ops_eio" = "$eio" ] && [ "$bytes_w" = 819200 ] && [ "$bytes_bad" = $((ok_reads_bad * 4096)) ]
result e2e-counters $?
fsyncs=$(grep '^obi_stat_fs_sync_duration_seconds_count{' "$LAB_RESULTS/metrics.txt" | grep 'error_type=""' | awk '{s+=$2} END {print s+0}')
echo "fsync: successful syncs=$fsyncs (want >=20)"
[ "$fsyncs" -ge 20 ]
result e2e-fsync $?
grep -iE 'level=(WARN|ERROR)' "$LAB_RESULTS/obi.log" | grep -iv 'imds\|kube\|cloud' | head -10

exit $fail
