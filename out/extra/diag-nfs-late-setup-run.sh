#!/bin/bash
# Diagnostic, not part of the lab kit: why is sunrpc still loaded when the final payload's
# "nfs late attach" step starts? Runs the same privileged tests, then looks at the module state.
set -u
echo "uname -r: $(uname -r)"
state() { echo "--- $1"; for m in nfs nfsv4 nfsv3 nfs_acl lockd grace sunrpc fscache netfs auth_rpcgss; do [ -e /sys/module/$m ] && echo "$m: refcnt=$(cat /sys/module/$m/refcnt 2>/dev/null) holders='$(ls /sys/module/$m/holders 2>/dev/null | tr '\n' ' ')' initstate=$(cat /sys/module/$m/initstate 2>/dev/null)"; done; grep -E 'rpc|nfs' /proc/mounts; }
state "before the tests"
./stats.test -test.v -test.run 'TestDisk|TestFsSync|TestNFS' -test.timeout 10m > "$LAB_RESULTS/privileged.log" 2>&1
echo "privileged rc=$?"; grep -E '^--- .*NFS' "$LAB_RESULTS/privileged.log"
state "after the tests"
echo "--- modprobe -r nfs (what the payload runs), verbose"
modprobe -r -v nfs; echo "rc=$?"
state "after modprobe -r nfs"
for t in 1 5 15; do sleep $t; modprobe -r -v nfs 2>&1; echo "after ${t}s more: modprobe -r nfs rc=$? sunrpc loaded=$([ -e /sys/module/sunrpc/initstate ] && echo yes || echo no)"; done
state "after the retries"
echo "--- modprobe -r of each module, verbose"
for m in nfsv4 nfsv3 nfs nfs_acl lockd grace auth_rpcgss sunrpc; do [ -e /sys/module/$m ] && { modprobe -r -v $m 2>&1; echo "$m rc=$?"; }; done
state "at the end"
[ ! -e /sys/module/sunrpc/initstate ]; echo "RESULT diag-sunrpc-unloaded-at-end $([ $? = 0 ] && echo PASS || echo FAIL)"
dmesg | grep -iE 'sunrpc|nfs|rpc' | tail -15
exit 0
