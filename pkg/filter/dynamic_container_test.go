// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package filter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/selection"
)

type emptyPIDSelector struct{}

func (emptyPIDSelector) GetPIDs() ([]app.PID, bool)        { return nil, false }
func (emptyPIDSelector) IncludesPID(app.PID) bool          { return false }
func (emptyPIDSelector) AddedPIDsNotify() <-chan []app.PID { return nil }
func (emptyPIDSelector) RemovedNotify() <-chan []app.PID   { return nil }

func TestByDynamicContainer_KeepsTheRecordsTheSelectionAllows(t *testing.T) {
	input := msg.NewQueue[[]string](msg.ChannelBufferLen(10))
	output := msg.NewQueue[[]string](msg.ChannelBufferLen(10))
	selectedContainer := func(tracker *selection.DynamicAppContainers, containerID string) bool {
		require.NotNil(t, tracker)
		return containerID == "aaaa"
	}

	run, err := ByDynamicContainer(emptyPIDSelector{}, nil, selectedContainer, input, output)(t.Context())
	require.NoError(t, err)
	out := output.Subscribe()
	go run(t.Context())

	input.Send([]string{"bbbb", "", "cccc"})
	input.Send([]string{"aaaa", "bbbb", "aaaa"})
	assert.Equal(t, []string{"aaaa", "aaaa"}, testutil.ReadChannel(t, out, timeout),
		"a batch without any selected record is not forwarded")
}

func TestByDynamicContainer_BypassedWithoutSelector(t *testing.T) {
	input := msg.NewQueue[[]string](msg.ChannelBufferLen(10))
	output := msg.NewQueue[[]string](msg.ChannelBufferLen(10))
	allowsNothing := func(*selection.DynamicAppContainers, string) bool { return false }

	run, err := ByDynamicContainer[string](nil, nil, allowsNothing, input, output)(t.Context())
	require.NoError(t, err)
	out := output.Subscribe()
	go run(t.Context())

	input.Send([]string{"aaaa", ""})
	assert.Equal(t, []string{"aaaa", ""}, testutil.ReadChannel(t, out, timeout))
}
