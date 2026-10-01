// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats // import "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

type pendingKey struct {
	device  string
	stacked bool
	op      ebpf.DiskOpCode
}

// pendingReader counts the reads and writes that each device is serving, as the kernel counts
// them for iostat. Unlike the accumulation readers, it reports every device that did I/O
// recently, including those that have no request in flight at the time of the read.
type pendingReader struct {
	log      *slog.Logger
	procRoot string
	devices  *deviceNames
	idleRead map[pendingKey]int
}

// observe tells the reader that a device completed reads or writes, so that it reports the
// device even if it never finds its requests in flight
func (p *pendingReader) observe(io *ebpf.DiskIO) {
	if !io.Op.IsTransfer() {
		return
	}
	p.idleRead[pendingKey{device: io.Device, stacked: io.Stacked, op: io.Op}] = 0
}

func newPendingReader(procRoot string, devices *deviceNames) *pendingReader {
	return &pendingReader{
		log:      dtlog().With("source", "diskstats"),
		procRoot: procRoot,
		devices:  devices,
		idleRead: map[pendingKey]int{},
	}
}

func (p *pendingReader) readStats() []*ebpf.Stat {
	busy, err := devicesInFlight(filepath.Join(p.procRoot, "diskstats"))
	if err != nil {
		// a partial read would undercount: skip it, the next read reports the current count
		p.log.Debug("can't read the requests in flight", "error", err)
		return nil
	}
	disks := map[string]*diskInFlight{}
	for _, numbers := range busy {
		reads, writes, err := readInflight(filepath.Join(p.devices.sysRoot, "dev", "block", numbers, "inflight"))
		if err != nil {
			// removed since
			continue
		}
		disk, partition := p.diskOf(numbers)
		if disk == "" {
			continue
		}
		counts := disks[disk]
		if counts == nil {
			counts = &diskInFlight{}
			disks[disk] = counts
		}
		if partition {
			counts.partitionReads += reads
			counts.partitionWrites += writes
		} else {
			counts.reads, counts.writes = reads, writes
		}
	}
	pending := map[pendingKey]int64{}
	for numbers, counts := range disks {
		major, minor := parseDevNumbers(numbers)
		device := p.devices.name(major, minor)
		stacked := p.devices.stacked(major, minor)
		if reads := max(counts.reads, counts.partitionReads); reads > 0 {
			pending[pendingKey{device: device, stacked: stacked, op: ebpf.CodeDiskOpRead}] = reads
		}
		if writes := max(counts.writes, counts.partitionWrites); writes > 0 {
			pending[pendingKey{device: device, stacked: stacked, op: ebpf.CodeDiskOpWrite}] = writes
		}
	}

	for key := range p.idleRead {
		if _, ok := pending[key]; !ok {
			p.idleRead[key]++
		}
	}
	var stats []*ebpf.Stat
	for key := range pending {
		p.idleRead[key] = 0
	}
	for key, idle := range p.idleRead {
		if idle > diskIdleReadsBeforeDelete {
			delete(p.idleRead, key)
			continue
		}
		stats = append(stats, &ebpf.Stat{
			Type: ebpf.StatTypeDiskPending,
			DiskPending: &ebpf.DiskPending{
				Device:   key.device,
				Stacked:  key.stacked,
				Op:       key.op,
				Requests: pending[key],
			},
		})
	}
	return stats
}

// diskInFlight is what a disk and its partitions report in flight. Before Linux 5.11, a disk
// doesn't count the requests of its partitions, which count their own: the larger of the two is
// what the disk serves, short of the requests on the whole disk while its partitions have some.
type diskInFlight struct {
	reads, writes                   int64
	partitionReads, partitionWrites int64
}

// diskOf returns the "major:minor" numbers of the disk of a block device, which is itself unless
// it is a partition, or an empty string if it was removed since
func (p *pendingReader) diskOf(numbers string) (disk string, partition bool) {
	dir := filepath.Join(p.devices.sysRoot, "dev", "block", numbers)
	if !exists(filepath.Join(dir, "partition")) {
		return numbers, false
	}
	// the sysfs directory of a partition is in the one of its disk
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", true
	}
	content, err := os.ReadFile(filepath.Join(filepath.Dir(resolved), "dev"))
	if err != nil {
		return "", true
	}
	return strings.TrimSpace(string(content)), true
}

// diskstatsInFlightField is the index of the "I/Os currently in progress" field in a line of
// /proc/diskstats, after the major and minor numbers and the device name
const diskstatsInFlightField = 11

// devicesInFlight returns the "major:minor" numbers of the block devices and partitions that
// have requests in flight, from /proc/diskstats
func devicesInFlight(diskstats string) ([]string, error) {
	f, err := os.Open(diskstats)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var busy []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) <= diskstatsInFlightField || fields[diskstatsInFlightField] == "0" {
			continue
		}
		busy = append(busy, fields[0]+":"+fields[1])
	}
	return busy, scanner.Err()
}

// readInflight reads the reads and writes in flight of a block device from its sysfs inflight
// file. The kernel counts flushes and discards as writes.
func readInflight(path string) (reads, writes int64, err error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, err
	}
	fields := strings.Fields(string(content))
	if len(fields) != 2 {
		return 0, 0, fmt.Errorf("unexpected content of %s: %q", path, content)
	}
	if reads, err = strconv.ParseInt(fields[0], 10, 64); err != nil {
		return 0, 0, err
	}
	if writes, err = strconv.ParseInt(fields[1], 10, 64); err != nil {
		return 0, 0, err
	}
	return reads, writes, nil
}

func parseDevNumbers(numbers string) (major, minor uint32) {
	ma, mi, _ := strings.Cut(numbers, ":")
	majorN, _ := strconv.ParseUint(ma, 10, 32)
	minorN, _ := strconv.ParseUint(mi, 10, 32)
	return uint32(majorN), uint32(minorN)
}
