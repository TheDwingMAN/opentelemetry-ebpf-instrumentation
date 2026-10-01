// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

// Set by userspace when an enabled block I/O metric reports an attribute that needs the cgroup
// the I/O is charged to (the container and Kubernetes attributes), or the partition it targets.
// Otherwise the probes don't read them, which saves a few kernel reads per request.
volatile const bool disk_read_cgroup;
volatile const bool disk_read_partition;
