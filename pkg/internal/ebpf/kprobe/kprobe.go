// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package kprobe // import "go.opentelemetry.io/obi/pkg/internal/ebpf/kprobe"

import (
	"errors"
	"io"
	"log/slog"
	"runtime"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/internal/ebpf/tracefs"
)

var attachPMU = func(symbol string, prog *ebpf.Program, ret bool) (io.Closer, error) {
	if ret {
		return link.Kretprobe(symbol, prog, nil)
	}
	return link.Kprobe(symbol, prog, nil)
}

var attachTraceFSEvent = tracefs.Attach

var defaultMaxActiveLog sync.Once

// Attach retries an EACCES from the PMU through tracefs, keeping the kernel's
// default maxactive for return probes.
func Attach(symbol string, prog *ebpf.Program, ret bool) (io.Closer, error) {
	return tracefs.WithFallback(tracefs.Kprobe,
		func() (io.Closer, error) { return attachPMU(symbol, prog, ret) },
		func() (io.Closer, error) { return attachTraceFS(symbol, prog, ret, 0) },
	)
}

// AttachRetprobe attaches a return probe that the kernel tracks for up to maxActive
// concurrent calls. Only tracefs can raise maxactive: PMU return probes always get
// the kernel's default. When tracefs can't be used, the probe is attached by Attach,
// with the default, and the returns of the calls beyond it are lost.
func AttachRetprobe(symbol string, prog *ebpf.Program, maxActive int) (io.Closer, error) {
	closer, traceErr := attachTraceFS(symbol, prog, true, maxActive)
	if traceErr == nil {
		return closer, nil
	}

	closer, err := Attach(symbol, prog, true)
	if err != nil {
		return nil, errors.Join(traceErr, err)
	}
	defaultMaxActiveLog.Do(func() {
		slog.Warn("tracefs can't be used, so return probes keep the kernel's default maxactive and can miss "+
			"the returns of concurrent calls; ensure tracefs is writable", "maxactive", maxActive, "error", traceErr)
	})
	return closer, nil
}

func attachTraceFS(symbol string, prog *ebpf.Program, ret bool, maxActive int) (io.Closer, error) {
	opts := tracefs.Options{Type: tracefs.Kprobe, Targets: []string{symbol}, Return: ret, MaxActive: maxActive}
	closer, err := attachTraceFSEvent(prog, opts)
	if !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.EINVAL) {
		return closer, err
	}

	// Match Cilium's retry for syscall names such as sys_connect.
	if prefix := syscallPrefix(); prefix != "" {
		opts.Targets = []string{prefix + symbol}
		return attachTraceFSEvent(prog, opts)
	}
	return closer, err
}

func syscallPrefix() string {
	switch runtime.GOARCH {
	case "amd64":
		return "__x64_"
	case "arm64":
		return "__arm64_"
	default:
		return ""
	}
}
