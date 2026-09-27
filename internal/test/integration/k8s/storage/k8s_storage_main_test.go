// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package storage exercises OBI's storage_block and storage_fs metrics
// against a kind cluster with a real, dynamically-provisioned NFS
// PersistentVolume (nfs-ganesha in-cluster server, kernel nfs.ko/nfsv4.ko
// client). Two kernel-dependent details worth knowing when this suite
// misbehaves:
//   - LOCALIO may short-circuit the wire: the NFS server shares the node's
//     kernel, so if nfs_localio is loaded NFS traffic can bypass the network
//     path. The nfs_file_* probes still fire correctly -- the instrumentation
//     path is fully exercised -- but do not use this suite to validate
//     latency *distributions*.
//   - The host's `nfs` kernel module must be loadable, since the client side
//     of the PVC mount uses it (nfs-ganesha, the in-cluster server, is
//     userspace and needs no module).
package storage

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/kube"
	k8s "go.opentelemetry.io/obi/internal/test/integration/k8s/common"
	"go.opentelemetry.io/obi/internal/test/integration/k8s/common/testpath"
	"go.opentelemetry.io/obi/internal/test/tools"
)

var cluster *kube.Kind

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		fmt.Println("skipping integration tests in short mode")
		return
	}

	if err := docker.Build(os.Stdout, tools.ProjectDir(),
		docker.ImageBuild{Tag: "obi:dev", Dockerfile: k8s.DockerfileOBI},
	); err != nil {
		slog.Error("can't build docker images", "error", err)
		os.Exit(-1)
	}

	cluster = kube.NewKind("test-kind-cluster-storage",
		kube.KindConfig(testpath.Manifests+"/00-kind-storage.yml"),
		kube.LocalImage("obi:dev"),
		kube.Deploy(testpath.Manifests+"/01-volumes.yml"),
		kube.Deploy(testpath.Manifests+"/01-serviceaccount.yml"),
		kube.Deploy(testpath.Manifests+"/01-nfs-provisioner.yml"),
		kube.Deploy(testpath.Manifests+"/02-prometheus-promscrape.yml"),
		kube.Deploy(testpath.Manifests+"/05-uninstrumented-nfs-writer.yml"),
		kube.Deploy(testpath.Manifests+"/06-obi-storage-promexport.yml"),
	)

	cluster.Run(m)
}

func TestStorageFsMetrics_Prom(t *testing.T) {
	cluster.TestEnv().Test(t, k8s.FeatureStorageFsMetrics())
}

func TestStorageBlockMetrics_Prom(t *testing.T) {
	cluster.TestEnv().Test(t, k8s.FeatureStorageBlockMetrics())
}
