// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import "io"

// watchMountTable has no mount-table change notification off Linux; the
// mount resolver then relies on its cache TTLs alone.
func watchMountTable(func(string, io.ReadSeeker), ...string) bool { return false }
