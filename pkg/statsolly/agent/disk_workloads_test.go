// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/filter"
)

func TestDiskReadsCgroup(t *testing.T) {
	selecting := func(metric attributes.Name, include ...string) attributes.Selection {
		return attributes.Selection{metric.Section: attributes.InclusionLists{Include: include}}
	}
	for _, tc := range []struct {
		name      string
		features  export.Features
		selection attributes.Selection
		filters   filter.AttributeFamilyConfig
		want      bool
	}{
		{name: "default attributes", features: export.FeatureStatsDisk},
		{
			name: "selected", features: export.FeatureStatsDiskOperations,
			selection: selecting(attributes.StatDiskOperations, "container.id"), want: true,
		},
		{
			name: "selected on a disabled metric", features: export.FeatureStatsDiskIO,
			selection: selecting(attributes.StatDiskOperations, "container.*"),
		},
		{
			name: "filtered, with underscores", features: export.FeatureStatsDiskIO,
			filters: filter.AttributeFamilyConfig{"container_id": {Match: "a1*"}}, want: true,
		},
		{
			name: "disk stats disabled", features: export.FeatureStatsTCPRtt,
			filters: filter.AttributeFamilyConfig{"container.id": {Match: "a1*"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attrSel, err := attributes.NewAttrSelector(attributes.UndefinedGroup, &attributes.SelectorConfig{SelectionCfg: tc.selection})
			require.NoError(t, err)
			assert.Equal(t, tc.want, diskReadsCgroup(tc.features, attrSel, tc.filters))
		})
	}
}
