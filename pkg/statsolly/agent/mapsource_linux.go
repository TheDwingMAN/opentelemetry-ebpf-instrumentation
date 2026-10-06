// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package agent // import "go.opentelemetry.io/obi/pkg/statsolly/agent"

import (
	ciliumebpf "github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
)

func newMapSource(m *ciliumebpf.Map) (statagg.Source, error) { return statagg.NewMapSource(m) }

func newSnapshotSource(m *ciliumebpf.Map) (statagg.Source, error) {
	return statagg.NewSnapshotSource(m)
}
