#!/bin/bash
# OBI BPF verifier test, statsolly subset.
echo "uname -r: $(uname -r)"
start=$(date +%s.%N)
./verifier.test -test.v -test.run 'TestBPFVerifierWithConstants/statsolly' -test.timeout 30m
rc=$?
echo "verifier rc=$rc ($(awk -v a=$start -v b=$(date +%s.%N) 'BEGIN{printf "%.1f", b-a}')s)"
exit $rc
