// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg/stataggtest"
)

const pendingTestTTL = 30 * time.Second

// pendingMap is a blk_rq_inflight-shaped in-memory map: one entry per
// request, holding issue_ns, dev and kind at the offsets Snapshot reads.
type pendingMap struct {
	m    *stataggtest.MemMap
	next uint64
}

func newPendingMap() *pendingMap {
	return &pendingMap{m: stataggtest.NewMemMap(8, pendingValueSize, 1)}
}

// put adds one in-flight request (a distinct raw key every time, as the
// request pointer or (dev, sector) key would be), issued issueNs ago, with
// no partition (step 13: part_dev 0, as on a node where it is not selected).
func (p *pendingMap) put(dev uint32, kind uint8, issueNs uint64) {
	p.putPart(dev, 0, kind, issueNs)
}

// putPart is put with a partition dev_t.
func (p *pendingMap) putPart(dev, partDev uint32, kind uint8, issueNs uint64) {
	key := make([]byte, 8)
	binary.NativeEndian.PutUint64(key, p.next)
	p.next++
	p.m.AddU64(key, 0, pendingValueIssueNs, issueNs)
	p.m.AddU32(key, 0, pendingValueDev, dev)
	p.m.AddU32(key, 0, pendingValuePartDev, partDev)
	p.m.AddU32(key, 0, pendingValueKind, uint32(kind)) // kind is the value's first byte; the rest is pad.
}

func TestPendingReader_CountsLiveEntriesByDevAndKind(t *testing.T) {
	pm := newPendingMap()
	pm.put(1, uint8(ebpf.CodeBlockRead), 100)
	pm.put(1, uint8(ebpf.CodeBlockRead), 100)
	pm.put(1, uint8(ebpf.CodeBlockWrite), 100)
	pm.put(2, uint8(ebpf.CodeBlockRead), 100)

	r := newPendingReader(func() time.Duration { return 1000 }, time.Now, pm.m)
	got, err := r.Snapshot(pendingTestTTL)
	require.NoError(t, err)

	assert.Equal(t, uint64(2), got[PendingKey{Dev: 1, Op: uint8(ebpf.CodeBlockRead)}])
	assert.Equal(t, uint64(1), got[PendingKey{Dev: 1, Op: uint8(ebpf.CodeBlockWrite)}])
	assert.Equal(t, uint64(1), got[PendingKey{Dev: 2, Op: uint8(ebpf.CodeBlockRead)}])
}

func TestPendingReader_IgnoresEntriesOlderThanTheSweepAge(t *testing.T) {
	const pollTime = 10 * time.Minute // enough for a 0-issued entry to be older than PendingSweepAge

	pm := newPendingMap()
	// A missed completion: issued long before the sweep age, never cleared.
	pm.put(1, uint8(ebpf.CodeBlockRead), 0)
	// A genuinely in-flight request, issued 10s before this poll.
	pm.put(1, uint8(ebpf.CodeBlockRead), uint64(pollTime-10*time.Second))

	r := newPendingReader(func() time.Duration { return pollTime }, time.Now, pm.m)
	got, err := r.Snapshot(pendingTestTTL)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), got[PendingKey{Dev: 1, Op: uint8(ebpf.CodeBlockRead)}],
		"the stale entry is not counted, only the fresh one")
}

func TestPendingReader_ReportsZeroForADeviceThatWentIdle(t *testing.T) {
	pm := newPendingMap()
	pm.put(1, uint8(ebpf.CodeBlockRead), 0)

	wall := time.Now()
	r := newPendingReader(func() time.Duration { return 0 }, func() time.Time { return wall }, pm.m)
	key := PendingKey{Dev: 1, Op: uint8(ebpf.CodeBlockRead)}

	got, err := r.Snapshot(pendingTestTTL)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), got[key])

	// The request completed: no entries left, but the device is still known.
	pm.m = stataggtest.NewMemMap(8, pendingValueSize, 1)
	r.sources = []statagg.Source{pm.m}
	wall = wall.Add(pendingTestTTL / 2)
	got, err = r.Snapshot(pendingTestTTL)
	require.NoError(t, err)
	require.Contains(t, got, key, "a recently active device reports zero, not nothing")
	assert.Zero(t, got[key])
}

// With storage_block_volumes the reader counts two maps: the requests in
// flight on the disks and the bios in flight on the stacked volumes. Their
// keys are pointers of different kinds, which may even be equal; the entries
// of both count, each under its own device.
func TestPendingReader_AddsUpTheRequestAndBioMaps(t *testing.T) {
	const disk, volume = 1, 2
	requests, bios := newPendingMap(), newPendingMap()
	requests.put(disk, uint8(ebpf.CodeBlockRead), 100)
	requests.put(disk, uint8(ebpf.CodeBlockWrite), 100)
	bios.put(volume, uint8(ebpf.CodeBlockWrite), 100)
	bios.put(volume, uint8(ebpf.CodeBlockWrite), 100)
	bios.putPart(volume, 3, uint8(ebpf.CodeBlockRead), 100)

	r := newPendingReader(func() time.Duration { return 1000 }, time.Now, requests.m, bios.m)
	got, err := r.Snapshot(pendingTestTTL)
	require.NoError(t, err)

	assert.Equal(t, map[PendingKey]uint64{
		{Dev: disk, Op: uint8(ebpf.CodeBlockRead)}:               1,
		{Dev: disk, Op: uint8(ebpf.CodeBlockWrite)}:              1,
		{Dev: volume, Op: uint8(ebpf.CodeBlockWrite)}:            2,
		{Dev: volume, PartDev: 3, Op: uint8(ebpf.CodeBlockRead)}: 1,
	}, got)
}

func TestPendingReader_DropsADeviceIdleForTheWholeTTL(t *testing.T) {
	pm := newPendingMap()
	pm.put(1, uint8(ebpf.CodeBlockRead), 0)

	wall := time.Now()
	r := newPendingReader(func() time.Duration { return 0 }, func() time.Time { return wall }, pm.m)
	key := PendingKey{Dev: 1, Op: uint8(ebpf.CodeBlockRead)}

	_, err := r.Snapshot(pendingTestTTL)
	require.NoError(t, err)

	pm.m = stataggtest.NewMemMap(8, pendingValueSize, 1)
	r.sources = []statagg.Source{pm.m}
	wall = wall.Add(pendingTestTTL + time.Second)
	got, err := r.Snapshot(pendingTestTTL)
	require.NoError(t, err)
	assert.NotContains(t, got, key, "a device idle for the whole TTL is omitted, not zeroed")
}

func TestPendingReader_SumsSeveralRawKeysOntoOneSeries(t *testing.T) {
	pm := newPendingMap()
	for range 5 {
		pm.put(1, uint8(ebpf.CodeBlockWrite), 0)
	}
	r := newPendingReader(func() time.Duration { return 0 }, time.Now, pm.m)
	got, err := r.Snapshot(pendingTestTTL)
	require.NoError(t, err)
	assert.Equal(t, uint64(5), got[PendingKey{Dev: 1, Op: uint8(ebpf.CodeBlockWrite)}])
}

func TestPendingKey_StatResolvesDeviceAndDirectionAttributes(t *testing.T) {
	key := PendingKey{Dev: 7, Op: uint8(ebpf.CodeBlockWrite)}
	s := key.Stat()
	require.NotNil(t, s.BlockIo)
	assert.Equal(t, uint32(7), s.BlockIo.Dev)
	assert.True(t, s.BlockIo.IsReadWrite())
}

// Step 13: part_dev is a field of the in-flight value, so pending_operations
// can break down by partition the same way the aggregated block metrics do.
func TestPendingReader_CountsByPartition(t *testing.T) {
	pm := newPendingMap()
	pm.putPart(1, 1|1<<8, uint8(ebpf.CodeBlockRead), 0)
	pm.putPart(1, 1|1<<8, uint8(ebpf.CodeBlockRead), 0)
	pm.putPart(1, 0, uint8(ebpf.CodeBlockRead), 0) // whole-disk I/O: no partition.

	r := newPendingReader(func() time.Duration { return 0 }, time.Now, pm.m)
	got, err := r.Snapshot(pendingTestTTL)
	require.NoError(t, err)

	assert.Equal(t, uint64(2), got[PendingKey{Dev: 1, PartDev: 1 | 1<<8, Op: uint8(ebpf.CodeBlockRead)}])
	assert.Equal(t, uint64(1), got[PendingKey{Dev: 1, Op: uint8(ebpf.CodeBlockRead)}],
		"whole-disk I/O is a distinct series from the partition's")
}

func TestPendingKey_StatResolvesPartitionAttribute(t *testing.T) {
	key := PendingKey{Dev: 1, PartDev: 2, Op: uint8(ebpf.CodeBlockWrite)}
	s := key.Stat()
	require.NotNil(t, s.BlockIo)
	assert.Equal(t, uint32(2), s.BlockIo.PartDev)
}

func TestPendingKey_StatHasNoDirectionForAFlushOrDiscard(t *testing.T) {
	for _, op := range []uint8{uint8(ebpf.CodeBlockFlush), uint8(ebpf.CodeBlockDiscard)} {
		s := PendingKey{Dev: 1, Op: op}.Stat()
		assert.False(t, s.BlockIo.IsReadWrite(), "op %d", op)
	}
}

func TestCollectPending_DropsAKeyTheDecoratorRejects(t *testing.T) {
	pm := newPendingMap()
	pm.put(1, uint8(ebpf.CodeBlockRead), 0)
	pm.put(2, uint8(ebpf.CodeBlockRead), 0)

	r := newPendingReader(func() time.Duration { return 0 }, time.Now, pm.m)
	decorate := func(s *ebpf.Stat) bool { return s.BlockIo.Dev != 2 }

	got, err := CollectPending(r, pendingTestTTL, decorate)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, uint32(1), got[0].Stat.BlockIo.Dev)
	assert.Equal(t, uint64(1), got[0].Value)
}

func TestCollectPending_KeepsEveryKeyWithNoDecorator(t *testing.T) {
	pm := newPendingMap()
	pm.put(1, uint8(ebpf.CodeBlockRead), 0)
	pm.put(2, uint8(ebpf.CodeBlockWrite), 0)

	r := newPendingReader(func() time.Duration { return 0 }, time.Now, pm.m)
	got, err := CollectPending(r, pendingTestTTL, nil)
	require.NoError(t, err)
	assert.Len(t, got, 2)
}
