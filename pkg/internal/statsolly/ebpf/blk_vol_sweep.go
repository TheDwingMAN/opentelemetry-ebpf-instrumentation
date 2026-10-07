// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"errors"
	"log/slog"
	"time"

	"github.com/cilium/ebpf"
)

const (
	// blkBioSweepInterval is how often the bio in-flight map is swept: often
	// enough that a volume whose bios never complete is caught before it
	// fills the map (see blkBioCrowdedAge). A pass over a map with few
	// entries is a handful of batch lookups.
	blkBioSweepInterval = 10 * time.Second
	// blkBioCrowdedAge is the stale age of a crowded map, one at least half
	// full. The map is shared by every tracked volume, and one whose bios
	// never complete fills it at its own I/O rate: a few thousand bios a
	// second fill 65536 entries in seconds, and every volume's bios are then
	// dropped until the dead volume's entries are BlockInflightStaleAge old.
	// No healthy volume has thousands of bios in flight for this long, so in
	// a crowded map an entry this old is taken for stale, and a volume that
	// leaves blkVolDeadBios of them is quarantined within two sweeps.
	blkBioCrowdedAge = 10 * time.Second
	// blkVolDeadBios is how many bios of one volume a sweep must find stale
	// to take the volume for one whose completions are not traced. A healthy
	// volume leaves one behind now and then: the kernel skips a run of a
	// program that is already running on the CPU (a completion in an
	// interrupt during another completion's program; S0-f: 1 in 4.8 million
	// runs), and a skipped completion leaves its entry. That is a handful a
	// minute at the highest rates, and they must not cost the volume its
	// metrics.
	blkVolDeadBios = 16
	// blkBioSweepBatch is the number of entries one batch lookup reads.
	blkBioSweepBatch = 4096
)

// bioInflight is the blk_bio_inflight map as the sweep uses it.
type bioInflight interface {
	// ForEach calls fn for every entry: the bio pointer and its value.
	ForEach(fn func(bio uint64, v *BlkBioBlkRqInflight)) error
	// DeleteIfQueuedAt deletes the entry of bio if it is still the one
	// queued at issueNs.
	DeleteIfQueuedAt(bio, issueNs uint64) error
}

// bioSweeper deletes the entries of blk_bio_inflight whose bio was queued
// more than BlockInflightStaleAge ago (blkBioCrowdedAge when the map is
// crowded), and hands the volumes that leave many of them over to
// quarantine.
//
// A completion can be missed (see blkVolDeadBios), and its entry would stay
// until the kernel reuses the struct bio. Worse, the bios of a bio-based
// device may never fire block_bio_complete at all: a driver that hands the
// bio it was given to a lower device, instead of a clone of it, has it
// completed as a request there, with its completion trace cleared (the NVMe
// multipath head does, which is why heads are not tracked; md raid0 and
// linear arrays do with queue/iostats=0; S0-b saw one completion per bio for
// dm-linear, dm-thin, md raid0 and raid1 on RHEL 9's 5.14). Every bio of
// such a volume would be left behind, counted as pending and never as
// completed, in a map that is a plain hash and evicts nothing.
type bioSweeper struct {
	log      *slog.Logger
	inflight bioInflight
	// capacity is the size of the map, which tells a crowded one.
	capacity   int
	monoNow    func() time.Duration // CLOCK_MONOTONIC, comparable to issue_ns
	quarantine func(dev uint32, stale int)

	// aged are the entries of the current pass older than blkBioCrowdedAge,
	// kept between passes for their storage.
	aged                  []agedBio
	logged, loggedCrowded bool
}

type agedBio struct {
	bio, issueNs uint64
	dev          uint32
	// stale: older than BlockInflightStaleAge.
	stale bool
}

// sweep runs one pass and returns the number of entries it found stale.
func (s *bioSweeper) sweep() int {
	now := s.monoNow()
	s.aged = s.aged[:0]
	entries := 0
	err := s.inflight.ForEach(func(bio uint64, v *BlkBioBlkRqInflight) {
		entries++
		age := now - time.Duration(int64(v.IssueNs))
		if age <= blkBioCrowdedAge {
			return
		}
		s.aged = append(s.aged, agedBio{bio: bio, issueNs: v.IssueNs, dev: v.Dev, stale: age > BlockInflightStaleAge})
	})
	if err != nil {
		s.log.Debug("can't read the in-flight bios", "error", err)
		return 0
	}

	crowded := s.capacity > 0 && 2*entries >= s.capacity
	olderThan := BlockInflightStaleAge
	if crowded {
		olderThan = blkBioCrowdedAge
	}
	perDev := map[uint32]int{}
	stale := 0
	for _, e := range s.aged {
		if !e.stale && !crowded {
			continue
		}
		stale++
		perDev[e.dev]++
		if err := s.inflight.DeleteIfQueuedAt(e.bio, e.issueNs); err != nil {
			s.log.Debug("can't delete a stale in-flight bio", "error", err)
		}
	}
	if stale == 0 {
		return 0
	}

	s.logStale(stale, olderThan, entries, crowded)
	dead := map[uint32]struct{}{}
	for dev, n := range perDev {
		if n >= blkVolDeadBios {
			s.quarantine(dev, n)
			dead[dev] = struct{}{}
		}
	}
	s.purge(dead)
	return stale
}

func (s *bioSweeper) logStale(stale int, olderThan time.Duration, entries int, crowded bool) {
	if crowded && !s.loggedCrowded {
		s.loggedCrowded = true
		s.log.Warn("the map of the bios in flight on stacked volumes is at least half full: bios left without"+
			" a completion for seconds are taken for lost, and the volumes that leave many are no longer measured",
			"entries", entries, "capacity", s.capacity, "bios", stale, "older_than", olderThan)
		return
	}
	if !s.logged {
		s.logged = true
		s.log.Info("bios of stacked volumes were left without a completion and are no longer counted as"+
			" pending: their completions were missed (see obi.bpf.storage.program.recursion.misses) or their volume hung",
			"bios", stale, "older_than", olderThan)
	}
}

// purge deletes every entry of the quarantined volumes: they are not
// tracked any more, so their bios in flight would be left until they are
// stale, holding room in the map and counted as pending.
func (s *bioSweeper) purge(dead map[uint32]struct{}) {
	if len(dead) == 0 {
		return
	}
	s.aged = s.aged[:0]
	err := s.inflight.ForEach(func(bio uint64, v *BlkBioBlkRqInflight) {
		if _, ok := dead[v.Dev]; ok {
			s.aged = append(s.aged, agedBio{bio: bio, issueNs: v.IssueNs})
		}
	})
	if err != nil {
		s.log.Debug("can't read the in-flight bios", "error", err)
		return
	}
	for _, e := range s.aged {
		if err := s.inflight.DeleteIfQueuedAt(e.bio, e.issueNs); err != nil {
			s.log.Debug("can't delete an in-flight bio of a quarantined volume", "error", err)
		}
	}
}

// bioInflightMap reads the kernel map in batches, or entry by entry on
// kernels without batch lookups (before 5.6).
type bioInflightMap struct {
	m       *ebpf.Map
	keys    []uint64
	values  []BlkBioBlkRqInflight
	noBatch bool
}

func newBioInflightMap(m *ebpf.Map) *bioInflightMap {
	n := min(blkBioSweepBatch, int(m.MaxEntries()))
	return &bioInflightMap{m: m, keys: make([]uint64, n), values: make([]BlkBioBlkRqInflight, n)}
}

func (b *bioInflightMap) ForEach(fn func(bio uint64, v *BlkBioBlkRqInflight)) error {
	if b.noBatch {
		return b.iterate(fn)
	}
	var cursor ebpf.MapBatchCursor
	for {
		n, err := b.m.BatchLookup(&cursor, b.keys, b.values, nil)
		for i := range n {
			fn(b.keys[i], &b.values[i])
		}
		switch {
		case errors.Is(err, ebpf.ErrKeyNotExist):
			return nil
		case errors.Is(err, ebpf.ErrNotSupported):
			b.noBatch = true
			return b.iterate(fn)
		case err != nil && n == 0 && len(b.keys) < int(b.m.MaxEntries()):
			// The only error a batch lookup that returns nothing recovers
			// from is a batch smaller than a hash bucket: double it and
			// start over. An entry seen twice is deleted once.
			size := min(2*len(b.keys), int(b.m.MaxEntries()))
			b.keys, b.values = make([]uint64, size), make([]BlkBioBlkRqInflight, size)
			cursor = ebpf.MapBatchCursor{}
		case err != nil:
			return err
		}
	}
}

func (b *bioInflightMap) iterate(fn func(bio uint64, v *BlkBioBlkRqInflight)) error {
	var bio uint64
	var v BlkBioBlkRqInflight
	iter := b.m.Iterate()
	for iter.Next(&bio, &v) {
		fn(bio, &v)
	}
	return iter.Err()
}

// DeleteIfQueuedAt looks the entry up again before deleting it: between the
// pass and the delete the kernel may have reused the struct bio for a new
// bio, whose entry is live.
func (b *bioInflightMap) DeleteIfQueuedAt(bio, issueNs uint64) error {
	var v BlkBioBlkRqInflight
	if err := b.m.Lookup(&bio, &v); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return err
	}
	if v.IssueNs != issueNs {
		return nil
	}
	if err := b.m.Delete(&bio); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}
