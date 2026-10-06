// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import attr "go.opentelemetry.io/obi/pkg/export/attributes/names"

// ProbeReads are the attributes that the storage probes read besides the reported ones
type ProbeReads struct {
	// Workloads makes the probes read the workload of every operation: dynamic application
	// selection keeps only the storage stats of the selected workloads
	Workloads bool
	// Filtered are the attributes that the stats attribute filters match, named with dots or
	// underscores
	Filtered []attr.Name
}
