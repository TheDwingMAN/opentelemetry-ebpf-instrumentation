// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package stats

import (
	"os"
	"testing"

	"go.opentelemetry.io/obi/pkg/internal/testutil"
)

// The privileged tests of this package and of the other storage package
// create loop devices and kubelet volume mounts, which the other's
// assertions would see: they never run at the same time.
func TestMain(m *testing.M) {
	unlock := testutil.LockHost("statsolly-privileged-tests")
	code := m.Run()
	unlock()
	os.Exit(code)
}
