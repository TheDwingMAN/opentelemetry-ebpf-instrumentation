// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/export"
)

func TestProbedFeatures(t *testing.T) {
	features := export.FeatureStatsTCPRtt | export.FeatureStatsDiskOperationDuration

	assert.Equal(t, features, probedFeatures(slog.Default(), features, false))
	assert.Equal(t, export.FeatureStatsTCPRtt, probedFeatures(slog.Default(), features, true),
		"disk stats are left out under dynamic selection, TCP stats are kept")
}
