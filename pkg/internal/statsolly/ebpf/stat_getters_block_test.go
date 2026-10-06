// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/otel/attribute"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func TestBlockIoGetters(t *testing.T) {
	// Point device-name resolution at an empty dir so it deterministically
	// falls back to the "<major>:<minor>" form regardless of the host's disks.
	withSysBlockDir(t, t.TempDir())

	s := &Stat{Type: StatTypeBlockIo, BlockIo: &BlockIo{Dev: 0x800010, Op: uint8(CodeDirectionWrite)}}

	devGetter, ok := StatGetters(attr.DiskDevice)
	assert.True(t, ok)
	assert.Equal(t, "8:16", devGetter(s).Value.Emit())

	opGetter, ok := StatGetters(attr.DiskIODirection)
	assert.True(t, ok)
	assert.Equal(t, "write", opGetter(s).Value.Emit())
}

// TestBlockIoStackedGetter covers the OTLP Bool vs Prometheus string split
// the step 8 device model needs: the same KeyValue carries a real boolean
// for OTLP and "true"/"false" for Prometheus.
func TestBlockIoStackedGetter(t *testing.T) {
	// Point device-name resolution at an empty dir so 0x800010 resolves to no
	// device, and the getter falls back to its unresolved default (false).
	withSysBlockDir(t, t.TempDir())

	s := &Stat{Type: StatTypeBlockIo, BlockIo: &BlockIo{Dev: 0x800010}}

	stackedGetter, ok := StatGetters(attr.DiskStacked)
	assert.True(t, ok)
	kv := stackedGetter(s)
	assert.Equal(t, attribute.BOOL, kv.Value.Type())
	assert.False(t, kv.Value.AsBool())

	stringGetter, ok := StatStringGetters(attr.DiskStacked)
	assert.True(t, ok)
	assert.Equal(t, "false", stringGetter(s))

	// A stat that carries no block I/O event resolves dev 0, which is also
	// unresolvable in the fixture, so the getter still returns a value
	// rather than panicking.
	notBlockIo := &Stat{Type: StatTypeTCPRtt, TCPRtt: &TCPRtt{}}
	assert.False(t, stackedGetter(notBlockIo).Value.AsBool())
}

// TestBlockIoErrorTypeGetter covers the platform-independent paths: no error,
// and a stat that carries no block I/O event. The errno-name-on-error path is
// platform-specific (errnoName only resolves names on unix); see
// stat_getters_block_unix_test.go.
func TestBlockIoErrorTypeGetter(t *testing.T) {
	errGetter, ok := StatGetters(attr.ErrorType)
	assert.True(t, ok)

	// No error: the attribute is omitted (an invalid KeyValue), not "".
	noError := &Stat{Type: StatTypeBlockIo, BlockIo: &BlockIo{Error: 0}}
	assert.False(t, errGetter(noError).Valid())

	notBlockIo := &Stat{Type: StatTypeTCPRtt, TCPRtt: &TCPRtt{}}
	assert.False(t, errGetter(notBlockIo).Valid())

	// Prometheus label sets are fixed: an omitted attribute is the empty
	// value, never Value.Emit()'s "unknown".
	errString, ok := StatStringGetters(attr.ErrorType)
	assert.True(t, ok)
	assert.Empty(t, errString(noError))
}

func TestBlockIoKinds(t *testing.T) {
	for _, tc := range []struct {
		op                        BlockOpCode
		readWrite, flush, discard bool
	}{
		{CodeBlockRead, true, false, false},
		{CodeBlockWrite, true, false, false},
		{CodeBlockFlush, false, true, false},
		{CodeBlockDiscard, false, false, true},
	} {
		b := &BlockIo{Op: uint8(tc.op)}
		assert.Equal(t, tc.readWrite, b.IsReadWrite(), "op %d", tc.op)
		assert.Equal(t, tc.flush, b.IsFlush(), "op %d", tc.op)
		assert.Equal(t, tc.discard, b.IsDiscard(), "op %d", tc.op)
	}

	var none *BlockIo
	assert.False(t, none.IsReadWrite())
	assert.False(t, none.IsFlush())
	assert.False(t, none.IsDiscard())
}

// TestBlockIoPartitionGetter covers obi.disk.partition: resolved to a name
// when set, omitted ("") for whole-disk I/O (PartDev 0) and for a Stat with
// no block I/O event.
func TestBlockIoPartitionGetter(t *testing.T) {
	withSysBlockDir(t, t.TempDir())

	partGetter, ok := StatStringGetters(attr.DiskPartition)
	assert.True(t, ok)

	wholeDisk := &Stat{Type: StatTypeBlockIo, BlockIo: &BlockIo{Dev: 0x800010, PartDev: 0}}
	assert.Empty(t, partGetter(wholeDisk), "whole-disk I/O has no partition")

	onPartition := &Stat{Type: StatTypeBlockIo, BlockIo: &BlockIo{Dev: 0x800010, PartDev: 0x800011}}
	assert.Equal(t, "8:17", partGetter(onPartition), "falls back to maj:min like deviceName")

	notBlockIo := &Stat{Type: StatTypeTCPRtt, TCPRtt: &TCPRtt{}}
	assert.Empty(t, partGetter(notBlockIo), "a stat with no block I/O event has no partition")
}

// Flushes and discards have no direction.
func TestBlockIoDirectionOfFlushAndDiscard(t *testing.T) {
	opGetter, ok := StatStringGetters(attr.DiskIODirection)
	assert.True(t, ok)
	for _, op := range []BlockOpCode{CodeBlockFlush, CodeBlockDiscard} {
		s := &Stat{Type: StatTypeBlockIo, BlockIo: &BlockIo{Op: uint8(op)}}
		assert.Empty(t, opGetter(s), "op %d", op)
	}
}
