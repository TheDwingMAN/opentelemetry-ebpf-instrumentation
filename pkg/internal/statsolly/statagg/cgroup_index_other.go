// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package statagg // import "go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"

import "io/fs"

func dirIno(fs.FileInfo) (uint64, bool) { return 0, false }
