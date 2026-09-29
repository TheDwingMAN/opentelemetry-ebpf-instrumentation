// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import "errors"

// statRootInode is Linux-only, like the probes that report root inodes.
func statRootInode(string) (uint64, error) { return 0, errors.New("unsupported") }
