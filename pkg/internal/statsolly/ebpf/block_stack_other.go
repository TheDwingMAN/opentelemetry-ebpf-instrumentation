// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

// devInfo is a block device's place in the stacking model. There is no
// sysfs off Linux, so every device resolves to itself, never stacked.
type devInfo struct {
	name        string
	stacked     bool
	isPartition bool
	parent      string
	physical    []string
}

// blockStack has nothing to walk off Linux: it reports every device as its
// own, unresolved physical device.
func blockStack(dev uint32) devInfo {
	return devInfo{name: deviceName(dev)}
}

// FSJoinDevice has no sysfs to resolve off Linux, and no host root to stat a
// mount source through, so it reports both fs join labels unresolved.
func FSJoinDevice(uint32, string) (systemDevice, physicalDevice string) {
	return "", ""
}
