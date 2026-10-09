// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/export"
)

func TestProbedFeatures(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
	features := export.FeatureStatsTCPRtt | export.FeatureStatsDiskServiceDuration

	assert.Equal(t, features, probedFeatures(log, features, false))
	assert.Equal(t, export.FeatureStatsTCPRtt, probedFeatures(log, export.FeatureStatsTCPRtt, true))
	assert.Empty(t, logs.String(), "no warning without storage stats under dynamic selection")

	assert.Equal(t, export.FeatureStatsTCPRtt, probedFeatures(log, features, true),
		"the storage stats are left out under dynamic selection, the TCP stats are kept")
	assert.Equal(t, 1, strings.Count(logs.String(), "level=WARN"), logs.String())
}
