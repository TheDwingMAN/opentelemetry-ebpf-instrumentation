// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package attributes

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func TestNormalize(t *testing.T) {
	incl := Selection{
		"obi_network_flow_bytes": InclusionLists{Include: []string{"foo", "bar"}},
		"some.other.metric_sum":  InclusionLists{Include: []string{"attr", "other"}},
		"tralari.tralara.total":  InclusionLists{Include: []string{"a1", "a2", "a3"}},
	}
	incl.Normalize()
	assert.Equal(t, Selection{
		"obi.network.flow":  InclusionLists{Include: []string{"foo", "bar"}},
		"some.other.metric": InclusionLists{Include: []string{"attr", "other"}},
		"tralari.tralara":   InclusionLists{Include: []string{"a1", "a2", "a3"}},
	}, incl)
}

func TestFor(t *testing.T) {
	p, err := NewAttrSelector(GroupKubernetes, &SelectorConfig{
		SelectionCfg: Selection{
			"obi.network.flow": InclusionLists{
				Include: []string{"obi.ip", "src.*", "k8s.*"},
				Exclude: []string{"k8s.*.name", "k8s.*.type", "*zone"},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, []attr.Name{
		"k8s.dst.namespace",
		"k8s.dst.node.ip",
		"k8s.src.namespace",
		"k8s.src.node.ip",
		"obi.ip",
		"src.address",
		"src.name",
		"src.port",
	}, p.For(NetworkFlow))
}

func TestFor_GlobEntries(t *testing.T) {
	// include all groups just to verify that other attributes aren't anyway selected
	p, err := NewAttrSelector(GroupKubernetes, &SelectorConfig{
		SelectionCfg: Selection{
			"*": InclusionLists{
				Include: []string{"obi.ip"},
				// won't be excluded from the final snapshot because they are
				// re-included in the next inclusion list
				Exclude: []string{"k8s.*.type"},
			},
			"obi.network.flow": InclusionLists{
				Include: []string{"src.*", "k8s.*"},
				Exclude: []string{"k8s.*.name", "*zone"},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, []attr.Name{
		"k8s.dst.namespace",
		"k8s.dst.node.ip",
		"k8s.dst.owner.type",
		"k8s.dst.type",
		"k8s.src.namespace",
		"k8s.src.node.ip",
		"k8s.src.owner.type",
		"k8s.src.type",
		"obi.ip",
		"src.address",
		"src.name",
		"src.port",
	}, p.For(NetworkFlow))
}

// if no include lists are defined, it takes the default arguments
func TestFor_GlobEntries_NoInclusion(t *testing.T) {
	p, err := NewAttrSelector(GroupKubernetes|GroupNetCIDR, &SelectorConfig{
		SelectionCfg: Selection{
			"*": InclusionLists{
				Exclude: []string{"*dst*"},
			},
			"obi.network.flow": InclusionLists{
				Exclude: []string{"k8s.*.namespace", "*zone"},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, []attr.Name{
		"direction",
		"k8s.cluster.name",
		"k8s.src.owner.name",
		"k8s.src.owner.type",
		"src.cidr",
	}, p.For(NetworkFlow))
}

func TestFor_GlobEntries_Order(t *testing.T) {
	// verify that policies are overridden from more generic to more concrete
	p, err := NewAttrSelector(0, &SelectorConfig{
		SelectionCfg: Selection{
			"*": InclusionLists{
				Include: []string{"*"},
			},
			"obi.network.*": InclusionLists{
				Exclude: []string{"dst.*", "transport", "*direction", "iface", "*zone"},
			},
			"obi.network.flow": InclusionLists{
				Include: []string{"dst.name"},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, []attr.Name{
		"client.port",
		"dst.name",
		"network.protocol.name",
		"network.type",
		"obi.ip",
		"server.port",
		"src.address",
		"src.name",
		"src.port",
	}, p.For(NetworkFlow))
}

func TestFor_GlobEntries_Order_Default(t *testing.T) {
	// verify that policies are overridden from more generic to more concrete
	var g AttrGroups
	g.Add(GroupAppKube)
	g.Add(GroupKubernetes)
	p, err := NewAttrSelector(g, &SelectorConfig{
		SelectionCfg: Selection{
			"*": InclusionLists{}, // assuming default set
			"http.*": InclusionLists{
				Exclude: []string{"*"},
			},
			"http.server.request.duration": InclusionLists{
				Include: []string{"url.path"},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, []attr.Name{
		"url.path",
	}, p.For(HTTPServerDuration))
}

func TestFor_KubeDisabled(t *testing.T) {
	p, err := NewAttrSelector(0, &SelectorConfig{
		SelectionCfg: Selection{
			"obi.network.flow": InclusionLists{
				Include: []string{"target.instance", "obi.ip", "src.*", "k8s.*"},
				Exclude: []string{"src.port", "*zone"},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, []attr.Name{
		"obi.ip",
		"src.address",
		"src.name",
	}, p.For(NetworkFlow))
}

func TestNilDoesNotCrash(t *testing.T) {
	assert.NotPanics(t, func() {
		p, err := NewAttrSelector(GroupKubernetes, &SelectorConfig{})
		require.NoError(t, err)
		assert.NotEmpty(t, p.For(NetworkFlow))
	})
}

func TestDefault(t *testing.T) {
	p, err := NewAttrSelector(GroupKubernetes, &SelectorConfig{})
	require.NoError(t, err)
	assert.Equal(t, []attr.Name{
		"direction",
		"k8s.cluster.name",
		"k8s.dst.namespace",
		"k8s.dst.owner.name",
		"k8s.dst.owner.type",
		"k8s.src.namespace",
		"k8s.src.owner.name",
		"k8s.src.owner.type",
	}, p.For(NetworkFlow))
	// the packets metric shares the same attribute groups as the bytes metric
	assert.Equal(t, p.For(NetworkFlow), p.For(NetworkFlowPackets))
}

func TestDefault_StatDiskNodeName(t *testing.T) {
	p, err := NewAttrSelector(GroupKubernetes, &SelectorConfig{})
	require.NoError(t, err)
	assert.Contains(t, p.For(StatDiskOperationDuration), attr.K8sNodeName)
	assert.Contains(t, p.For(StatDiskIO), attr.K8sNodeName)
	assert.Contains(t, p.For(StatDiskQueueDepth), attr.K8sNodeName)
	assert.Contains(t, p.For(StatDiskPendingOperations), attr.K8sNodeName)
	assert.Contains(t, p.For(StatDiskPendingOperations), attr.DiskStacked)
	assert.Contains(t, p.For(StatDiskOperations), attr.K8sNodeName)
	assert.Contains(t, p.For(StatDiskOperationTime), attr.DiskStacked)
}

func TestFor_KubeDisabled_StatDiskOmitsNodeName(t *testing.T) {
	p, err := NewAttrSelector(0, &SelectorConfig{})
	require.NoError(t, err)
	assert.NotContains(t, p.For(StatDiskOperationDuration), attr.K8sNodeName)
}

func TestDefault_StatFsOwnerAndNodeName(t *testing.T) {
	p, err := NewAttrSelector(GroupKubernetes, &SelectorConfig{})
	require.NoError(t, err)
	got := p.For(StatFsOperationDuration)
	assert.Contains(t, got, attr.K8sNodeName)
	assert.Contains(t, got, attr.K8sOwnerName)
	// k8s.kind is opt-in, to bound cardinality.
	assert.NotContains(t, got, attr.K8sKind)
}

func TestFor_KubeDisabled_StatFsOmitsNodeNameAndOwner(t *testing.T) {
	p, err := NewAttrSelector(0, &SelectorConfig{})
	require.NoError(t, err)
	got := p.For(StatFsOperationDuration)
	assert.NotContains(t, got, attr.K8sNodeName)
	assert.NotContains(t, got, attr.K8sOwnerName)
}

func TestDefault_DBClientDuration(t *testing.T) {
	p, err := NewAttrSelector(0, &SelectorConfig{})
	require.NoError(t, err)
	assert.Equal(t, []attr.Name{
		attr.DBNamespace,
		attr.DBOperation,
		attr.DBResponseStatusCode,
		attr.DBSystemName,
		attr.ErrorType,
		attr.ServerAddr,
		attr.ServerPort,
	}, p.For(DBClientDuration))
}

func TestDefault_DBServerDuration(t *testing.T) {
	p, err := NewAttrSelector(0, &SelectorConfig{})
	require.NoError(t, err)
	assert.Equal(t, []attr.Name{
		attr.DBNamespace,
		attr.DBOperation,
		attr.DBResponseStatusCode,
		attr.DBSystemName,
		attr.ErrorType,
		attr.ServerAddr,
		attr.ServerPort,
	}, p.For(DBServerDuration))
}

func TestDefault_HTTPServerMetrics(t *testing.T) {
	p, err := NewAttrSelector(0, &SelectorConfig{})
	require.NoError(t, err)
	for _, def := range []Name{HTTPServerDuration, HTTPServerRequestSize, HTTPServerResponseSize} {
		assert.Equal(t, []attr.Name{
			attr.ErrorType,
			attr.HTTPRequestMethod,
			attr.HTTPResponseStatusCode,
			attr.ServerAddr,
			attr.ServerPort,
			attr.HTTPURLScheme,
		}, p.For(def), def.Section)
	}
}

func TestDefault_HTTPClientMetrics(t *testing.T) {
	p, err := NewAttrSelector(0, &SelectorConfig{})
	require.NoError(t, err)
	for _, def := range []Name{HTTPClientDuration, HTTPClientRequestSize, HTTPClientResponseSize} {
		assert.Equal(t, []attr.Name{
			attr.ErrorType,
			attr.HTTPRequestMethod,
			attr.HTTPResponseStatusCode,
			attr.ServerAddr,
			attr.ServerPort,
			attr.HTTPURLScheme,
		}, p.For(def), def.Section)
	}
}

func TestExplicitlyIncluded(t *testing.T) {
	for _, tc := range []struct {
		name      string
		selection Selection
		expected  bool
	}{
		{name: "no user selection", selection: nil, expected: false},
		{name: "selection for another metric", selection: Selection{
			"http.client.request.duration": InclusionLists{Include: []string{"server.port"}},
		}, expected: false},
		{name: "exact name", selection: Selection{
			"db.client.operation.duration": InclusionLists{Include: []string{"server.port"}},
		}, expected: true},
		{name: "prom-style name", selection: Selection{
			"db_client_operation_duration": InclusionLists{Include: []string{"server_port"}},
		}, expected: true},
		{name: "attribute glob", selection: Selection{
			"db.client.operation.duration": InclusionLists{Include: []string{"server.*"}},
		}, expected: true},
		{name: "metric and attribute globs", selection: Selection{
			"*": InclusionLists{Include: []string{"*"}},
		}, expected: true},
		{name: "unrelated include", selection: Selection{
			"db.client.operation.duration": InclusionLists{Include: []string{"db.collection.name"}},
		}, expected: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.selection.Normalize()
			p, err := NewAttrSelector(0, &SelectorConfig{SelectionCfg: tc.selection})
			require.NoError(t, err)
			assert.Equal(t, tc.expected, p.ExplicitlyIncluded(DBClientDuration, attr.ServerPort))
		})
	}
}

func TestDefaultSensitiveQueryParamsIncludesLegacyAWSSignedURLKeys(t *testing.T) {
	assert.Contains(t, DefaultSensitiveQueryParams, "AWSAccessKeyId")
	assert.Contains(t, DefaultSensitiveQueryParams, "Signature")
	assert.Contains(t, DefaultSensitiveQueryParams, "SecurityToken")
}

func TestExtraGroupAttributes(t *testing.T) {
	var g AttrGroups
	g.Add(GroupKubernetes)
	g.Add(GroupAppKube)
	p, err := NewAttrSelector(g, &SelectorConfig{
		ExtraGroupAttributesCfg: map[string][]attr.Name{
			"k8s_app_meta": {"k8s.app.version"},
			"test":         {"test"},
		},
	})
	require.NoError(t, err)
	assert.ElementsMatch(t, []attr.Name{
		"error.type",
		"http.request.method",
		"http.response.status_code",
		"k8s.cluster.name",
		"k8s.container.name",
		"k8s.daemonset.name",
		"k8s.deployment.name",
		"k8s.job.name",
		"k8s.cronjob.name",
		"k8s.kind",
		"k8s.namespace.name",
		"k8s.node.name",
		"k8s.owner.name",
		"k8s.pod.name",
		"k8s.pod.start_time",
		"k8s.pod.uid",
		"k8s.replicaset.name",
		"k8s.statefulset.name",
		"server.address",
		"server.port",
		"url.scheme",
		"k8s.app.version",
	}, p.For(HTTPServerRequestSize))
}

func TestTraces(t *testing.T) {
	p, err := NewAttrSelector(GroupTraces, &SelectorConfig{
		SelectionCfg: Selection{
			"traces": InclusionLists{
				Include: []string{"db.query.text", "db.response.error", "obi.ip", "src.*", "k8s.*"},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, []attr.Name{
		"db.query.text",
		"db.response.error",
	}, p.For(Traces))
}

func TestTracesGenAIToolCallAttributes(t *testing.T) {
	p, err := NewAttrSelector(GroupTraces, &SelectorConfig{
		SelectionCfg: Selection{
			"traces": InclusionLists{
				Include: []string{"gen_ai.tool.call.*"},
			},
		},
	})
	require.NoError(t, err)
	assert.Empty(t, p.For(Traces))

	p, err = NewAttrSelector(GroupTraces, &SelectorConfig{
		SelectionCfg: Selection{
			"traces": InclusionLists{
				Include: []string{
					"gen_ai.tool.call.arguments",
					"gen_ai.tool.call.result",
				},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, []attr.Name{
		"gen_ai.tool.call.arguments",
		"gen_ai.tool.call.result",
	}, p.For(Traces))

	p, err = NewAttrSelector(GroupTraces, &SelectorConfig{
		SelectionCfg: Selection{
			"traces": InclusionLists{
				Include: []string{"gen_ai.*"},
				Exclude: []string{"gen_ai.input.messages", "gen_ai.output.messages"},
			},
		},
	})
	require.NoError(t, err)
	assert.NotContains(t, p.For(Traces), attr.GenAIToolCallArguments)
	assert.NotContains(t, p.For(Traces), attr.GenAIToolCallResult)
}

// A Section with an underscore of its own is selected by its own name, in
// any notation: the selection keys are normalized (underscores to dots, unit
// and aggregation suffixes removed), so the Section is matched normalized
// too.
func TestFor_SectionWithUnderscore(t *testing.T) {
	for _, name := range []Section{
		"obi.stat.disk.pending_operations",
		"obi_stat_disk_pending_operations",
		"obi.stat.disk.pending_*",
	} {
		t.Run(string(name), func(t *testing.T) {
			sel := Selection{name: InclusionLists{Include: []string{"disk.io.direction"}}}
			sel.Normalize()
			p, err := NewAttrSelector(GroupKubernetes, &SelectorConfig{SelectionCfg: sel})
			require.NoError(t, err)
			assert.Equal(t, []attr.Name{attr.DiskIODirection}, p.For(StatDiskPendingOperations))
			assert.Contains(t, p.For(StatDiskIO), attr.DiskDevice, "another metric is untouched")
		})
	}
}

// storage_block_pod (D11): the pod counters carry namespace, pod and owner by
// default, container and kind on request; obi.stat.disk.io gets the same pod
// attributes only when the flag counts it per cgroup.
func TestDefault_BlockPodAttributes(t *testing.T) {
	pod, err := NewAttrSelector(GroupKubernetes|GroupStatsBlockPod, &SelectorConfig{})
	require.NoError(t, err)
	podDefaults := []attr.Name{
		attr.DiskIODirection, attr.K8sNamespaceName, attr.K8sOwnerName, attr.K8sPodName, attr.DiskDevice,
		attr.DiskStacked, attr.K8sNodeName,
	}
	for _, m := range []Name{StatDiskOperations, StatDiskOperationTime, StatDiskIO} {
		assert.ElementsMatch(t, podDefaults, pod.For(m), m.OTEL)
	}

	noPod, err := NewAttrSelector(GroupKubernetes, &SelectorConfig{})
	require.NoError(t, err)
	assert.ElementsMatch(t, []attr.Name{attr.DiskIODirection, attr.DiskDevice, attr.DiskStacked, attr.K8sNodeName},
		noPod.For(StatDiskIO),
		"without storage_block_pod, disk.io has no pod attributes")

	noKube, err := NewAttrSelector(GroupStatsBlockPod, &SelectorConfig{})
	require.NoError(t, err)
	assert.ElementsMatch(t, []attr.Name{attr.DiskIODirection, attr.DiskDevice, attr.DiskStacked}, noKube.For(StatDiskOperations),
		"without Kubernetes metadata, the pod counters are per device and direction")

	sel := Selection{"obi_stat_disk_operations_total": InclusionLists{Include: []string{"k8s.container.name", "k8s.kind"}}}
	sel.Normalize()
	optIn, err := NewAttrSelector(GroupKubernetes|GroupStatsBlockPod, &SelectorConfig{SelectionCfg: sel})
	require.NoError(t, err)
	assert.Equal(t, []attr.Name{attr.K8sContainerName, attr.K8sKind}, optIn.For(StatDiskOperations))
	assert.NotContains(t, optIn.For(StatDiskOperations), attr.DiskPartition, "the pod counters are per device")
}
