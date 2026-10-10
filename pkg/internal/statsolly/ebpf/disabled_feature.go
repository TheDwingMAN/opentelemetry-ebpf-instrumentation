// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

// DisabledFeature is an enabled storage stat feature whose probes can't be loaded or attached on
// this node. The stats agent runs without it, as OBI runs without an optional tracer that can't be
// loaded.
type DisabledFeature struct {
	// Feature names the metrics and the features that enable them
	Feature string
	// Reason is why their probes can't be loaded or attached
	Reason string
}
