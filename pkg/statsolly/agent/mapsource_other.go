// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package agent // import "go.opentelemetry.io/obi/pkg/statsolly/agent"

import (
	"errors"

	ciliumebpf "github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
)

func newMapSource(*ciliumebpf.Map) (statagg.Source, error) {
	return nil, errors.New("kernel aggregation maps are only read on Linux")
}
