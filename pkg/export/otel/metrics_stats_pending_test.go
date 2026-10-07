// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric/embedded"

	metric2 "go.opentelemetry.io/obi/pkg/export/otel/metric/api/metric"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

// fakeInt64Observer records every Observe call a callback makes, as the
// real SDK's observer would during a collection, so pendingCallback can be
// tested without a Meter.
type fakeInt64Observer struct {
	embedded.Int64Observer
	values []int64
	sets   []attribute.Set
}

func (o *fakeInt64Observer) Observe(value int64, opts ...metric2.ObserveOption) {
	cfg := metric2.NewObserveConfig(opts)
	o.values = append(o.values, value)
	o.sets = append(o.sets, cfg.Attributes())
}

// devProject is a minimal Projection that collapses a BlockIo stat's device
// alone, as a real one does when disk.io.direction is not selected: it is
// not storageProjection's job this test is probing, but pendingCallback's
// grouping of whatever a Projection collapses.
func devProject(s *ebpf.Stat) (string, attribute.Set) {
	key := fmt.Sprint(s.BlockIo.Dev)
	return key, attribute.NewSet(attribute.String("system.device", key))
}

func TestPendingCallback_SumsPointsAProjectionCollapsesOntoOneSeries(t *testing.T) {
	points := []ebpf.PendingPoint{
		{Stat: &ebpf.Stat{BlockIo: &ebpf.BlockIo{Dev: 1, Op: uint8(ebpf.CodeBlockRead)}}, Value: 2},
		{Stat: &ebpf.Stat{BlockIo: &ebpf.BlockIo{Dev: 1, Op: uint8(ebpf.CodeBlockWrite)}}, Value: 3},
		{Stat: &ebpf.Stat{BlockIo: &ebpf.BlockIo{Dev: 2, Op: uint8(ebpf.CodeBlockRead)}}, Value: 5},
	}
	cb := pendingCallback(func() ([]ebpf.PendingPoint, error) { return points, nil }, devProject)

	obs := &fakeInt64Observer{}
	require.NoError(t, cb(t.Context(), obs))

	got := map[string]int64{}
	for i, set := range obs.sets {
		dev, _ := set.Value("system.device")
		got[dev.AsString()] = obs.values[i]
	}
	assert.Equal(t, map[string]int64{"1": 5, "2": 5}, got)
}

func TestPendingCallback_ObservesNothingWhenTheSnapshotIsEmpty(t *testing.T) {
	cb := pendingCallback(func() ([]ebpf.PendingPoint, error) { return nil, nil }, devProject)

	obs := &fakeInt64Observer{}
	require.NoError(t, cb(t.Context(), obs))
	assert.Empty(t, obs.values)
}

func TestPendingCallback_PropagatesASnapshotError(t *testing.T) {
	wantErr := errors.New("batch lookup failed")
	cb := pendingCallback(func() ([]ebpf.PendingPoint, error) { return nil, wantErr }, devProject)

	obs := &fakeInt64Observer{}
	assert.ErrorIs(t, cb(context.Background(), obs), wantErr)
}
