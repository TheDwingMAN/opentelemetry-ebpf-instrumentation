// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package testutil // import "go.opentelemetry.io/obi/pkg/internal/testutil"

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// LockHost takes an exclusive lock named name, shared by every test binary
// on the host, and returns its release. go test runs the binaries of several
// packages at once; the privileged tests of those that change host-wide
// state (loop devices, mounts under /var/lib/kubelet that the filesystem
// probes react to) take it in their TestMain so that one package's devices
// and mounts never show up in another's assertions. When the lock file can't
// be opened, the tests run unlocked. A test binary that a locked one runs
// (a test re-executing itself in a child process) inherits the lock rather
// than waiting for its parent to release it.
func LockHost(name string) (unlock func()) {
	held := "OBI_TEST_HOST_LOCK_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
	if os.Getenv(held) != "" {
		return func() {}
	}
	f, err := os.OpenFile(filepath.Join(os.TempDir(), "obi-"+name+".lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return func() {}
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		f.Close()
		return func() {}
	}
	_ = os.Setenv(held, "1")
	return func() { f.Close() }
}
