#!/bin/bash
# Summarizes the latest disk payload run of each kernel into a markdown table.
cd "$(dirname "$0")" || exit 1
echo "| Kernel | Verifier | Privileged (loop exact / cgroup split / fsync) | e2e histogram | e2e counters | e2e fsync |"
echo "|---|---|---|---|---|---|"
for k in v5.8.18 v5.10.270 v5.15.221 v6.1.188 v6.6.157 v6.12.111 v6.18.54 v7.2.6; do
  d=$(ls -td runs/$k-*/ 2>/dev/null | head -1)
  o=$d/results/output.log
  p=$d/results/privileged.log
  r() { grep -q "RESULT $1 PASS" $o && echo PASS || echo FAIL; }
  priv=$(for t in TestDiskLatencyIsAccumulatedPerDevice TestDiskIOIsChargedPerCgroup TestFsSyncIsChargedPerCgroup; do grep -qE -- "--- PASS: $t" $p && printf P || printf F; done)
  echo "| $k | $(r verifier) | $priv | $(r e2e-histogram) | $(r e2e-counters) | $(r e2e-fsync) |"
done
