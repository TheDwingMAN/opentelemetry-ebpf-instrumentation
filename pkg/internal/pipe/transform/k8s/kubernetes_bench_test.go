// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"testing"

	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/kube"
)

// BenchmarkMetadataDecorator_StorageStat measures what the network metadata
// decorator does per storage stat, which has no endpoints to decorate it by.
func BenchmarkMetadataDecorator_StorageStat(b *testing.B) {
	dec := newTestDecorator(b, kube.NewStore(&fakeNotifier{}, kube.ResourceLabels{}, nil, imetrics.NoopReporter{}))
	dec.clusterName = "prod"

	type item struct{ attrs pipe.CommonAttrs }
	attrsOf := func(i *item) *pipe.CommonAttrs { return &i.attrs }
	isStorage := func(*item) bool { return true }
	items := make([]*item, 1)

	b.ReportAllocs()
	for b.Loop() {
		items[0] = &item{}
		decorateAll(items, attrsOf, dec, isStorage)
	}
}
