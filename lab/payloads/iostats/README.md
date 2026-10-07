# iostats payload

Does the current v2 `obi` time a request from a stale `rq->start_time_ns` when the device has
`queue/iostats=0`? Kernels from 6.13 stamp the field only for accounted requests (`RQF_IO_STAT`),
and tags are reused, so a request issued with iostats=0 can carry the stamp of an earlier use.
v2 reads the field in `bpf/statsolly/tp_blk.c` (`record_issue`, `kernel_timed_start`,
`never_issued_start`).

In the lab kit, `../../build-payload.sh iostats` builds `obi` from the OBI checkout and writes
`COMMIT` and `MODE` (see Run). The cloud lab's copy ran a hard link of `../final/obi`, built from
23410d280, whose BPF and Go code are identical to 9be5912a1.

## What it does

Per device (loop on a 256M file in /tmp, the virtio disk with serial `lab-extra-1`, null_blk) and
per scheduler (`none`, then `mq-deadline`), all I/O pinned to CPU 0:

- **A**, iostats=1: 2048 direct 4k reads, then (write-back caches only) 32 writes each followed by
  an fsync, which sends an empty PREFLUSH. The kernel stamps the tags in use.
- **B**, iostats=0, at least 8 s after A (above the 5 s top finite bucket): 256 reads and the same
  32 writes + fsyncs. Stale on 6.13+: the queue time and the flush latency come out as the age.
- **C**, iostats=1 after 8 s: control, the same device timed correctly.
- A witness dumps CPU 0's tag-bitmap word from debugfs before A, after A and after B. The hint
  itself moves (freed tags wait in the deferred-clear mask, so the tags walk through the word), the
  word does not, and A walks through every bit of it.
- **D**, null_blk `nr_devices=2 shared_tags=1`: nullb0 is accounted, then nullb1 (iostats=0) reuses
  the shared tags.

Start of the output: `uname -r`, `grep -c -a __RQF_IO_STAT` on `/sys/kernel/btf/vmlinux`,
`queue_iostats_passthrough_show` in kallsyms, and every block device's scheduler, iostats and
wbt_lat_usec. Then the sha256 of `obi` and its `disk_rqf_*` counts, `RESULT binary-matches-mode`
(`disk_rqf_io_stat` count 0 for the current binary, above 0 for a fixed one).

## Run

    cd ~/obi-work/lab-kit/lab
    ./build-payload.sh iostats      # MODE: fixed if obi has disk_rqf_io_stat; IOSTATS_MODE=fixed|current forces it
    LAB_EXTRA_DISKS="1G" ./run-vm.sh v6.18.54 payloads/iostats 1800
    LAB_EXTRA_DISKS="1G" ./run-matrix.sh payloads/iostats 1800 v6.18.54 v7.2.6 v6.12.111 rhel9.6 \
      rhel8.10 v5.8.18 v5.10.270 v5.15.221 v6.1.188 v6.6.157 rhel8.9

To end within 600 s on TCG, no combination starts when it could end after `IOSTATS_BUDGET` (570 s,
estimated as 1.25 times the longest so far; `SKIP ... time budget` says so), and every wait ends
before 595 s. A combination took about 33 s natively.
Without `LAB_EXTRA_DISKS` the virtio combinations are skipped. For a binary with the iostats gate,
`MODE` holds `fixed` and every kernel expects CLEAN. Build with `IOSTATS_MODE=fixed` when the
checkout must have the gate: `binary-matches-mode` then fails on a build without it.
Knobs (environment, for manual runs): `IOSTATS_N_A N_B K W BUDGET HARD`.

## Result lines

`RESULT positive|control|witness|stale-queue|stale-flush-<device>-<scheduler>`, `INFO` with the numbers
behind each, `SKIP <name> <reason>` for a missing device, scheduler, write cache, debugfs file or
time. Names use the kernel's device name; D uses `nullb1-shared`.

`stale-*` passes when the observed class equals the expected one (STALE from 6.13, else CLEAN) and
positive, control and witness pass. So PASS on 6.18/7.2 means the defect reproduced. `INFO verdict`
says REPRODUCED, ABSENT, INCONCLUSIVE (a prerequisite failed), CONTRADICTION (STALE on an older
kernel, CLEAN on 6.13+ with every prerequisite passing) or UNEXPLAINED (MIXED).

## Expected with the current binary

| Kernels | Class | Phase B signature |
|---|---|---|
| v5.8.18, v5.10.270, v5.15.221, v6.1.188, v6.6.157, v6.12.111, rhel9.6, rhel8.9, rhel8.10 | CLEAN | `none`: queue count 0 for reads and writes (start 0 is unknown), write-back devices ops_w about K (empty flushes dropped). `mq-deadline`: queue count (read) = 256, all <= 0.1 s; ops_w about 2K with kernel writes 0 (a known parity difference, not an outlier). RHEL 8: the same, all through `record_issue`. |
| v6.18.54, v7.2.6 | STALE, every device and scheduler | q_inf (read) about 256, mean >= 8 s; the 32 data writes stale too; write-back devices ops_w about 63, over5s about 31, operation_time >= 224 s, kernel writes 0. C clean. D STALE. |

The same payload on this host's 6.18.44 kernel (loop0, both schedulers, no OBI changes) gave
STALE for queue and flush with positive, control and witness passing; null_blk, virtio and D need
the lab.
