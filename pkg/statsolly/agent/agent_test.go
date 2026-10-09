// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/export"
)

// Under dynamic application selection, the cache flushes, which are charged to no container, are
// never exported: OBI warns at startup when they are enabled then
func TestWarnUnselectableFlushes(t *testing.T) {
	var logs bytes.Buffer
	restore := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(restore) })
	const warning = "metric=obi.stat.disk.flush.duration"

	disk := export.FeatureStatsDisk
	withoutFlushes := export.FeatureStatsDisk &^ export.FeatureStatsDiskFlush
	warnUnselectableFlushes(&disk, false)
	warnUnselectableFlushes(&withoutFlushes, true)
	assert.NotContains(t, logs.String(), warning)

	warnUnselectableFlushes(&disk, true)
	assert.Contains(t, logs.String(), warning)
}
