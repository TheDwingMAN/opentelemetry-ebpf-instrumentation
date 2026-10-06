// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	ciliumebpf "github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
)

type StatsFetcher struct{}

// NFSConfig is how the NFS client RPC programs count.
type NFSConfig struct {
	Exponential  bool
	KernelBounds []uint64
	Owner        bool
	CgroupV1     bool
}

func NewStatsFetcher(_ *config.EBPFTracer, _ *export.Features, _ *attributes.SelectorConfig, _ NFSConfig) (*StatsFetcher, error) {
	return nil, nil
}

// Close any resources that are taken
func (m *StatsFetcher) Close() error {
	return nil
}

func (m *StatsFetcher) StatsEventsMap() *ciliumebpf.Map {
	return nil
}

func (m *StatsFetcher) DebugEventsMap() *ciliumebpf.Map {
	return nil
}

func (m *StatsFetcher) NFSRPCMap() *ciliumebpf.Map {
	return nil
}
