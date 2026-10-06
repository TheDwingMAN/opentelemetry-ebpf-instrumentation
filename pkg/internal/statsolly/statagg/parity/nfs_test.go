// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package parity

import (
	"log/slog"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg/stataggtest"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/stats"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/meta"
)

// nfsBuckets are the default buckets with the NFS histogram's bounds
// differing between the exporters: the kernel counts in their union.
func nfsBuckets() (otelBuckets, promBuckets export.Buckets) {
	otelBuckets, promBuckets = export.DefaultBuckets, export.DefaultBuckets
	promBuckets.StatNFSClientRPCDurationHistogram = []float64{0.0005, 0.002, 0.01, 0.1, 1, 10, 30}
	return otelBuckets, promBuckets
}

// nfsEvents is a deterministic stream of NFS RPC attempts: NFSv3 and NFSv4
// calls to an IPv4, an IPv6 and a link-local server, with the error statuses
// S0-c observed, a few retransmissions, execute times from 1 us to 20 s,
// and values exactly on and next to each bound. avoid keeps execute times
// 2 ns away from its bounds, as blockEvents does.
func nfsEvents(n int, bounds []uint64, avoid bool) []*ebpf.Stat {
	rnd := rand.New(rand.NewPCG(21, 22))
	servers := []ebpf.NFSRPC{
		{Family: 2, Addr: [16]byte{192, 168, 122, 34}},
		{Family: 10, Addr: [16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 1}},
		{Family: 10, Addr: [16]byte{0xfe, 0x80, 15: 2}, ScopeID: 2},
	}
	calls := []struct {
		version uint8
		statIdx uint16
		status  []int32
	}{
		{3, 3, []int32{-2}},           // LOOKUP, ENOENT
		{3, 6, []int32{-13}},          // READ, EACCES
		{3, 7, []int32{-528}},         // WRITE, EJUKEBOX
		{4, 18, []int32{-10008, -13}}, // OPEN: DELAY, EACCES
		{4, 1, []int32{-13}},          // READ
	}
	execute := func() uint64 {
		for {
			v := uint64(math.Pow(10, 3+rnd.Float64()*7.3))
			if !avoid || !nearBound(bounds, v) {
				return v
			}
		}
	}
	events := make([]*ebpf.Stat, 0, n)
	for i := range n {
		rpc := servers[rnd.IntN(len(servers))]
		call := calls[rnd.IntN(len(calls))]
		rpc.Version, rpc.StatIdx = call.version, call.statIdx
		if rnd.IntN(8) == 0 {
			rpc.Status = call.status[rnd.IntN(len(call.status))]
		}
		if rnd.IntN(20) == 0 {
			rpc.Retransmits = uint64(rnd.IntN(3) + 1)
		}
		// Headers and payload: a call is usually small, a reply can carry a
		// page of data (READ) or none (LOOKUP, WRITE).
		rpc.TxBytes = uint64(100 + rnd.IntN(400))
		rpc.RxBytes = uint64(rnd.IntN(4096) + 40)
		rpc.ExecuteNs = execute()
		if !avoid && i < 2*len(bounds) {
			rpc.ExecuteNs = bounds[i/2] + uint64(i%2)
		}
		events = append(events, &ebpf.Stat{Type: ebpf.StatTypeNFSRPC, NFSRPC: &rpc})
	}
	return events
}

func nfsKernel(t *testing.T, layout *statagg.Layout, features export.Features) func(decorate func(*ebpf.Stat) bool) Kernel {
	return func(decorate func(*ebpf.Stat) bool) Kernel {
		n, err := stataggtest.NewNFS(layout, features, decorate)
		require.NoError(t, err)
		return Kernel{Registry: n.Registry, Families: []*statagg.Family{n.Family}, Record: n.Record}
	}
}

func TestParity_NFSExplicitBuckets(t *testing.T) {
	otelBuckets, promBuckets := nfsBuckets()
	layout, err := statagg.NewExplicitLayout(otelBuckets.StatNFSClientRPCDurationHistogram, promBuckets.StatNFSClientRPCDurationHistogram)
	require.NoError(t, err)
	Run(t, Setup{Features: export.FeatureStorageNFS, OTelBuckets: otelBuckets, PromBuckets: promBuckets},
		nfsEvents(3000, layout.BoundsNs, false), nfsKernel(t, layout, export.FeatureStorageNFS))
}

func TestParity_NFSExponentialBuckets(t *testing.T) {
	layout, err := statagg.NewExponentialLayout(statagg.DefaultExponentialScale)
	require.NoError(t, err)
	Run(t, Setup{
		Features:    export.FeatureStorageNFS,
		OTelBuckets: export.DefaultBuckets,
		PromBuckets: export.DefaultBuckets,
		Exponential: true,
	}, nfsEvents(3000, layout.BoundsNs, true), nfsKernel(t, layout, export.FeatureStorageNFS))
}

// Without storage_nfs_errors the kernel keeps no status, and the duration
// and retransmits series are the ones the per-event path merges.
func TestParity_NFSWithoutErrors(t *testing.T) {
	features := export.FeatureStorageNFSDuration | export.FeatureStorageNFSRetransmits
	layout, err := statagg.NewExplicitLayout(export.DefaultBuckets.StatNFSClientRPCDurationHistogram)
	require.NoError(t, err)
	Run(t, Setup{Features: features, OTelBuckets: export.DefaultBuckets, PromBuckets: export.DefaultBuckets},
		nfsEvents(1000, layout.BoundsNs, false), nfsKernel(t, layout, features))
}

// With only storage_nfs_io on, the kernel keeps no status and the duration
// and retransmits words are never read: the per-event path is the one that
// merges tx and rx into the series the aggregated path's two variants feed.
func TestParity_NFSIOOnly(t *testing.T) {
	features := export.FeatureStorageNFSIo
	layout, err := statagg.NewExplicitLayout(export.DefaultBuckets.StatNFSClientRPCDurationHistogram)
	require.NoError(t, err)
	Run(t, Setup{Features: features, OTelBuckets: export.DefaultBuckets, PromBuckets: export.DefaultBuckets},
		nfsEvents(1000, layout.BoundsNs, false), nfsKernel(t, layout, features))
}

func TestParity_NFSFiltersAndSelection(t *testing.T) {
	layout, err := statagg.NewExplicitLayout(export.DefaultBuckets.StatNFSClientRPCDurationHistogram)
	require.NoError(t, err)
	for name, setup := range map[string]Setup{
		"procedure filter": {Filters: filter.AttributeFamilyConfig{
			"onc_rpc.procedure.name": filter.MatchDefinition{Match: "READ"},
		}},
		"error filter": {Filters: filter.AttributeFamilyConfig{
			"error.type": filter.MatchDefinition{NotMatch: "ENOENT"},
		}},
		"no server": {Selection: attributes.Selection{
			attributes.StatNFSClientRPCDuration.Section: attributes.InclusionLists{Exclude: []string{"server.address"}},
			attributes.StatNFSClientRPCErrors.Section:   attributes.InclusionLists{Include: []string{"error.type"}},
		}},
		// Without network.io.direction the two variants merge into one
		// series per server: both paths must agree on the sum.
		"no direction": {Selection: attributes.Selection{
			attributes.StatNFSClientIO.Section: attributes.InclusionLists{Exclude: []string{"network.io.direction"}},
		}},
	} {
		t.Run(name, func(t *testing.T) {
			setup.Features = export.FeatureStorageNFS
			setup.OTelBuckets, setup.PromBuckets = export.DefaultBuckets, export.DefaultBuckets
			Run(t, setup, nfsEvents(1000, layout.BoundsNs, false), nfsKernel(t, layout, export.FeatureStorageNFS))
		})
	}
}

// The default NFS buckets reach 10 s: the attempt after a JUKEBOX, which
// includes the client's 5 s backoff, is counted below +Inf.
func TestNFSDefaultBucketsHoldTheJukeboxBackoff(t *testing.T) {
	bounds := export.DefaultBuckets.StatNFSClientRPCDurationHistogram
	require.Len(t, bounds, 16)
	require.GreaterOrEqual(t, bounds[len(bounds)-1], (5200 * time.Millisecond).Seconds())
	layout, err := statagg.NewExplicitLayout(bounds, bounds)
	require.NoError(t, err)
	require.Len(t, layout.Bounds, 16)
}

func cgroupID(tb testing.TB, path string) uint64 {
	tb.Helper()
	var st syscall.Stat_t
	require.NoError(tb, syscall.Stat(path, &st))
	return st.Ino
}

// nfsOwners builds a cgroup index and a Kubernetes store with two pods, the
// first with two cgroups (a pod slice and a container scope below it), and
// returns the owner ids to spread RPCs over: those two, the second pod's, a
// cgroup in no pod, a cgroup the index never finds, and 0.
func nfsOwners(t *testing.T) (owners []uint64, decorate func(*ebpf.Stat)) {
	t.Helper()
	root := t.TempDir()
	const (
		podA = "kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod90b1ecb8_b850_451a_97c6_c073b5ddbb53.slice"
		podB = "kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod11111111_2222_3333_4444_555555555555.slice"
	)
	dirs := []string{podA, podA + "/cri-containerd-" + "aaaa.scope", podB, "system.slice/nfs-client.service"}
	for _, d := range dirs {
		require.NoError(t, os.MkdirAll(filepath.Join(root, d), 0o755))
	}
	index := statagg.NewCgroupIndex(statagg.WithCgroupRoots(root))
	require.NoError(t, index.Scan())
	for _, d := range dirs {
		owners = append(owners, cgroupID(t, filepath.Join(root, d)))
	}
	owners = append(owners, 1<<40, 0)

	n := meta.NewBaseNotifier(slog.Default())
	store := kube.NewStore(&n, kube.ResourceLabels{}, nil, nil)
	for _, p := range []struct{ uid, ns, name, owner string }{
		{"90b1ecb8-b850-451a-97c6-c073b5ddbb53", "ns-a", "pod-a", "deploy-a"},
		{"11111111-2222-3333-4444-555555555555", "ns-b", "pod-b", ""},
	} {
		pod := &informer.PodInfo{Uid: p.uid}
		if p.owner != "" {
			pod.Owners = []*informer.Owner{{Name: p.owner, Kind: "Deployment"}}
		}
		require.NoError(t, store.On(&informer.Event{
			Type:     informer.EventType_CREATED,
			Resource: &informer.ObjectMeta{Name: p.name, Namespace: p.ns, Kind: "Pod", Pod: pod},
		}))
	}
	return owners, stats.NewNFSOwnerDecorator(store, index, false)
}

// With a pod attribute selected the kernel keys carry the submitting cgroup:
// owners that resolve to the same pod, and those that resolve to nothing,
// merge into one series each, exactly as the per-event path's decorated
// stats do. With the attributes deselected, every owner collapses into one
// series per server and procedure.
func TestParity_NFSOwner(t *testing.T) {
	layout, err := statagg.NewExplicitLayout(export.DefaultBuckets.StatNFSClientRPCDurationHistogram)
	require.NoError(t, err)
	podAttrs := []string{"k8s.namespace.name", "k8s.pod.name", "k8s.owner.name"}
	selected := attributes.Selection{}
	for _, m := range []attributes.Name{
		attributes.StatNFSClientRPCDuration, attributes.StatNFSClientRPCErrors,
		attributes.StatNFSClientRPCRetransmits, attributes.StatNFSClientIO,
	} {
		selected[m.Section] = attributes.InclusionLists{Include: podAttrs}
	}
	for name, selection := range map[string]attributes.Selection{
		"pod attributes selected":   selected,
		"pod attributes deselected": {},
	} {
		t.Run(name, func(t *testing.T) {
			owners, ownerDecorate := nfsOwners(t)
			events := nfsEvents(3000, layout.BoundsNs, false)
			for i, e := range events {
				e.NFSRPC.Owner = owners[i%len(owners)]
			}
			// The per-event path gets the decorated stats; the kernel's
			// keys are decorated by the family.
			perEvent := make([]*ebpf.Stat, len(events))
			for i, e := range events {
				rpc := *e.NFSRPC
				perEvent[i] = &ebpf.Stat{Type: ebpf.StatTypeNFSRPC, NFSRPC: &rpc}
				ownerDecorate(perEvent[i])
			}
			setup := Setup{
				Features: export.FeatureStorageNFS, Selection: selection,
				OTelBuckets: export.DefaultBuckets, PromBuckets: export.DefaultBuckets,
			}
			Run(t, setup, perEvent, func(decorate func(*ebpf.Stat) bool) Kernel {
				n, err := stataggtest.NewNFS(layout, export.FeatureStorageNFS, func(s *ebpf.Stat) bool {
					ownerDecorate(s)
					return decorate(s)
				})
				require.NoError(t, err)
				return Kernel{Registry: n.Registry, Families: []*statagg.Family{n.Family}, Record: n.Record}
			})
		})
	}
}
