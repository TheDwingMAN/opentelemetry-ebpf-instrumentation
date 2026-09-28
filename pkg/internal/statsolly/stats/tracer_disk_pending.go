// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats // import "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"

import (
	"log/slog"
	"maps"
	"slices"
	"time"

	ciliumebpf "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

// staleRequestAge is how long after its issue an entry of disk_rq_start stops counting as a
// request in flight. Devices time out and complete (or fail) requests much sooner, so older
// entries are requests whose completion was not seen, which the LRU map evicts eventually.
const staleRequestAge = 10 * time.Minute

// requestSource abstracts the disk_rq_start and disk_bio_start eBPF maps, for testing
type requestSource interface {
	requests() ([]ebpf.StatsDiskRqStartT, error)
}

type ebpfRequests struct {
	// the block requests in flight, and the bios in flight of the stacked volumes (nil unless they
	// are measured)
	starts, bioStarts *ciliumebpf.Map
}

func (e ebpfRequests) requests() ([]ebpf.StatsDiskRqStartT, error) {
	requests, err := inFlightEntries(e.starts)
	if err != nil || e.bioStarts == nil {
		return requests, err
	}
	bios, err := inFlightEntries(e.bioStarts)
	return append(requests, bios...), err
}

// inFlightEntries returns the values of a map of requests or bios in flight, keyed by their address. The
// kernel deletes entries while the map is iterated, and the iteration starts over from the first
// entry when the entry at the cursor is gone, so the entries are deduplicated by key.
func inFlightEntries(starts *ciliumebpf.Map) ([]ebpf.StatsDiskRqStartT, error) {
	byAddress := map[uint64]ebpf.StatsDiskRqStartT{}
	var key uint64
	var start ebpf.StatsDiskRqStartT
	iter := starts.Iterate()
	for iter.Next(&key, &start) {
		byAddress[key] = start
	}
	return slices.Collect(maps.Values(byAddress)), iter.Err()
}

type pendingKey struct {
	device  string
	stacked bool
	op      ebpf.DiskOpCode
}

// pendingReader counts the reads and writes that each device is serving, from the requests in
// flight that the kernel tracks, or the bios in flight for the stacked volumes. Unlike the accumulation readers, it reports every device that did
// I/O recently, including those that have no request in flight at the time of the read.
type pendingReader struct {
	log      *slog.Logger
	source   requestSource
	devices  *deviceNames
	nowNs    func() uint64
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

func newPendingReader(source requestSource, devices *deviceNames) *pendingReader {
	return &pendingReader{
		log:      dtlog().With("map", "disk_rq_start"),
		source:   source,
		devices:  devices,
		nowNs:    monotonicNs,
		idleRead: map[pendingKey]int{},
	}
}

// monotonicNs is the time of the clock that bpf_ktime_get_ns reads
func monotonicNs() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	return uint64(ts.Nano())
}

func (p *pendingReader) readStats() []*ebpf.Stat {
	requests, err := p.source.requests()
	if err != nil {
		// a partial read would undercount: skip it, the next read reports the current count
		p.log.Debug("can't read the requests in flight", "error", err)
		return nil
	}
	now := p.nowNs()
	pending := map[pendingKey]int64{}
	for _, request := range requests {
		op := ebpf.DiskOpCode(request.Op)
		if !op.IsTransfer() || now-request.IssuedNs > uint64(staleRequestAge) {
			continue
		}
		pending[pendingKey{
			device:  p.devices.name(request.Major, request.Minor),
			stacked: p.devices.stacked(request.Major, request.Minor),
			op:      op,
		}]++
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
