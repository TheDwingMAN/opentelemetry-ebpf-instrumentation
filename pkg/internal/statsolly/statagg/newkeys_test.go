// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package statagg_test

import (
	"context"
	"encoding/binary"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg/stataggtest"
)

// The map of these tests counts operations per cgroup: its key is a cgroup
// id, its value one u64 counter.
const (
	cgKeySize   = 8
	cgValueSize = 8
)

var testOps = attributes.Name{Section: "test.ops", OTEL: "test.ops", Prom: "test_ops_total"}

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// cluster is what the decoration knows of the node: the pod of each live
// cgroup, as the cgroup index and the Kubernetes store answer while the pod
// exists, and the cgroups whose pod the store does not know yet.
type cluster struct {
	mu          sync.Mutex
	pods        map[uint64]string
	pending     map[uint64]bool
	decorations int
}

func newCluster() *cluster {
	return &cluster{pods: map[uint64]string{}, pending: map[uint64]bool{}}
}

func (c *cluster) setPod(cgid uint64, pod string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pods[cgid] = pod
	delete(c.pending, cgid)
}

// podGone removes a pod, its processes and its cgroup.
func (c *cluster) podGone(cgid uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.pods, cgid)
}

func (c *cluster) setPending(cgid uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pending[cgid] = true
}

func (c *cluster) decorate(s *ebpf.Stat) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.decorations++
	if pod, ok := c.pods[uint64(s.BlockIo.Dev)]; ok {
		s.CommonAttrs.Metadata = map[attr.Name]string{attr.K8sPodName: pod}
	}
	return true
}

func (c *cluster) isPending(s *ebpf.Stat) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pending[uint64(s.BlockIo.Dev)]
}

func (c *cluster) decorated() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.decorations
}

func cgStat(key, _ []byte) (*ebpf.Stat, bool) {
	return &ebpf.Stat{Type: ebpf.StatTypeBlockIo, BlockIo: &ebpf.BlockIo{Dev: binary.NativeEndian.Uint32(key)}}, true
}

func cgKey(cgid uint64) []byte {
	return binary.NativeEndian.AppendUint64(nil, cgid)
}

type newKeysFamily struct {
	family   *statagg.Family
	m        *stataggtest.MemMap
	clock    *testClock
	cluster  *cluster
	producer *statagg.Producer
}

// newKeysTestFamily is a family of a MemMap on cpus CPUs whose keys are
// decorated with their pod by a cluster; tune changes its config.
func newKeysTestFamily(t *testing.T, cpus int, tune func(*statagg.Config)) *newKeysFamily {
	t.Helper()
	nf := &newKeysFamily{
		m:       stataggtest.NewMemMap(cgKeySize, cgValueSize, cpus),
		clock:   &testClock{now: time.Unix(1_700_000_000, 0)},
		cluster: newCluster(),
	}
	cfg := statagg.Config{
		Name:     "test_new_keys",
		Source:   nf.m,
		Layout:   statagg.ValueLayout{Counters: 1, Monotonic: true},
		Stat:     cgStat,
		Decorate: nf.cluster.decorate,
		Pending:  nf.cluster.isPending,
		Metrics: []*statagg.Metric{{
			Name: testOps, Kind: statagg.KindCounter,
			Value: func(d statagg.Delta) uint64 { return d.Counter(0) },
		}},
		TickInterval:    time.Hour,
		RedecorateAfter: time.Hour,
		Clock:           nf.clock.Now,
	}
	if tune != nil {
		tune(&cfg)
	}
	f, err := statagg.NewFamily(cfg)
	require.NoError(t, err)
	reg, err := statagg.NewRegistry(f)
	require.NoError(t, err)
	nf.family = f

	nf.producer = statagg.NewProducer(reg, "test",
		func(sdkmetric.InstrumentKind) metricdata.Temporality { return metricdata.CumulativeTemporality }, 0)
	byPod := func(s *ebpf.Stat) (string, attribute.Set) {
		pod := s.CommonAttrs.Metadata[attr.K8sPodName]
		return pod, attribute.NewSet(attribute.String("pod", pod))
	}
	require.NoError(t, nf.producer.Add(testOps, statagg.OTelMetric{Project: byPod}))
	return nf
}

// record counts n operations of cgroup cgid on cpu, as the kernel does.
func (nf *newKeysFamily) record(cgid uint64, cpu int, n uint64) {
	nf.m.AddU64(cgKey(cgid), cpu, 0, n)
}

// check advances the clock by a new-key interval and runs the check.
func (nf *newKeysFamily) check() {
	nf.clock.Advance(statagg.DefaultNewKeyInterval)
	nf.family.CheckNewKeys()
}

// opsByPod collects the family, as a scrape does.
func (nf *newKeysFamily) opsByPod(t *testing.T) map[string]int64 {
	t.Helper()
	sm, err := nf.producer.Produce(context.Background())
	require.NoError(t, err)
	out := map[string]int64{}
	for _, s := range sm {
		for _, m := range s.Metrics {
			for _, dp := range m.Data.(metricdata.Sum[int64]).DataPoints {
				pod, _ := dp.Attributes.Value("pod")
				out[pod.AsString()] = dp.Value
			}
		}
	}
	return out
}

var cpuCases = []int{1, 4}

// A pod shorter than the gap between scrapes and ticks: its key is
// decorated by the first new-key check after its first count, while the pod
// exists, so everything it counted is the pod's; and while no key is new,
// the checks read no value.
func TestFamily_NewKeyIsDecoratedWithinOneCheck(t *testing.T) {
	for _, cpus := range cpuCases {
		t.Run(strconv.Itoa(cpus)+"cpus", func(t *testing.T) {
			nf := newKeysTestFamily(t, cpus, nil)
			nf.record(3, 0, 100) // a long-lived pod's cgroup
			nf.cluster.setPod(3, "server")
			nf.family.Start()
			nf.check()
			require.Equal(t, 1, nf.m.Reads(), "the first check finds every key new")

			for range 5 {
				nf.record(3, 0, 1)
				nf.check()
			}
			assert.Equal(t, 1, nf.m.Reads(), "no new key: the checks only list the keys")
			assert.Equal(t, 6, nf.m.Listings())

			nf.cluster.setPod(7, "short-job")
			nf.record(7, cpus-1, 3)
			nf.check()
			assert.Equal(t, 2, nf.m.Reads(), "a new key: one poll")
			assert.Equal(t, 2, nf.cluster.decorated())

			// The pod ends: its processes, cgroup and store entry go.
			nf.cluster.podGone(7)
			for range 20 {
				nf.record(7, 0, 2)
				nf.check()
			}
			assert.Equal(t, 2, nf.m.Reads(), "no new key: no read")
			assert.Equal(t, 2, nf.cluster.decorated())

			assert.Equal(t, map[string]int64{"server": 105, "short-job": 43}, nf.opsByPod(t),
				"the next scrape counts what the pod did after it was gone into its series")
		})
	}
}

// A new key whose decoration is not final (a pod the store does not know
// yet) has the checks poll again while it is young, so it is decorated
// again with its pod as soon as the store knows it.
func TestFamily_NewKeyCheckRetriesPendingDecorations(t *testing.T) {
	nf := newKeysTestFamily(t, 4, nil)
	nf.family.Start()
	nf.cluster.setPending(7)
	nf.record(7, 0, 1)
	nf.check()
	require.Equal(t, 1, nf.m.Reads())

	nf.record(7, 1, 1)
	nf.check()
	assert.Equal(t, 2, nf.m.Reads(), "a pending key: the check polls again")
	assert.Equal(t, 2, nf.cluster.decorated())

	nf.cluster.setPod(7, "job")
	nf.record(7, 2, 1)
	nf.check()
	assert.Equal(t, 3, nf.m.Reads())
	assert.Equal(t, 3, nf.cluster.decorated(), "decorated again once its pod is known")

	nf.record(7, 3, 1)
	nf.check()
	assert.Equal(t, 3, nf.m.Reads(), "final: no more polls")
	assert.Equal(t, map[string]int64{"": 2, "job": 2}, nf.opsByPod(t))
}

// A key whose pod never resolves has the checks poll for RetryPendingFor
// after it appeared, no longer.
func TestFamily_NewKeyCheckRetriesForABoundedTime(t *testing.T) {
	nf := newKeysTestFamily(t, 1, nil)
	nf.family.Start()
	nf.cluster.setPending(7)
	nf.record(7, 0, 1)
	for range 30 {
		nf.check()
		nf.record(7, 0, 1)
	}
	retries := int(statagg.DefaultRetryPendingFor / statagg.DefaultNewKeyInterval)
	assert.Equal(t, retries, nf.m.Reads(), "the first poll and its retries, until the key is no longer young")
}

// Learn runs before the poll that decorates the new keys, outside the
// family lock: a scrape it lets through decorates them, and the check then
// does not read the map again.
func TestFamily_NewKeyCheckLearnsBeforePolling(t *testing.T) {
	var nf *newKeysFamily
	var learnt [][]byte
	var scraped map[string]int64
	nf = newKeysTestFamily(t, 4, func(c *statagg.Config) {
		c.Learn = func(keys [][]byte) {
			learnt = append(learnt, keys...)
			// The cgroup index learns the pod's cgroup, and a scrape
			// comes in meanwhile: the family is not locked.
			nf.cluster.setPod(7, "job")
			scraped = nf.opsByPod(t)
		}
	})
	nf.family.Start()
	nf.record(7, 1, 5)
	nf.check()
	assert.Equal(t, [][]byte{cgKey(7)}, learnt)
	assert.Equal(t, map[string]int64{"job": 5}, scraped)
	assert.Equal(t, 1, nf.m.Reads(), "the scrape read the map: the check does not again")

	nf.record(7, 1, 1)
	nf.check()
	assert.Len(t, learnt, 1, "only new keys are learnt")
}

// The checks' polls delete idle keys after IdleAfter, as the tick's do:
// polling more often makes no key idle sooner.
func TestFamily_NewKeyCheckKeepsIdleAfter(t *testing.T) {
	nf := newKeysTestFamily(t, 4, func(c *statagg.Config) { c.TickInterval = 30 * time.Second })
	nf.family.Start()
	nf.record(3, 0, 1)
	nf.check()
	idleAfter := statagg.DefaultIdleAfter(30 * time.Second)

	nf.clock.Advance(idleAfter - 2*statagg.DefaultNewKeyInterval)
	nf.record(4, 0, 1)
	nf.check()
	assert.Equal(t, 2, nf.m.Reads())
	assert.Equal(t, 2, nf.m.Len(), "idle for less than IdleAfter: kept")

	nf.clock.Advance(statagg.DefaultNewKeyInterval)
	nf.record(5, 0, 1)
	nf.check()
	assert.Equal(t, 3, nf.m.Reads())
	assert.Equal(t, 2, nf.m.Len(), "idle for IdleAfter: deleted")
}

// Once the family stopped, the checks list nothing: the map may be closed.
func TestFamily_NewKeyCheckStopsWithTheFamily(t *testing.T) {
	nf := newKeysTestFamily(t, 4, nil)
	nf.family.Start()
	nf.family.Stop()
	nf.record(7, 0, 1)
	nf.check()
	assert.Zero(t, nf.m.Listings())
	assert.Equal(t, 1, nf.m.Reads(), "the last read of Stop only")
}

// Run checks for new keys every NewKeyInterval.
func TestFamily_RunChecksForNewKeys(t *testing.T) {
	nf := newKeysTestFamily(t, 4, func(c *statagg.Config) {
		c.NewKeyInterval = 10 * time.Millisecond
		c.Clock = time.Now
	})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		nf.family.Run(ctx)
		close(done)
	}()
	nf.cluster.setPod(7, "job")
	nf.record(7, 0, 1)
	require.Eventually(t, func() bool { return nf.cluster.decorated() == 1 }, 5*time.Second, 5*time.Millisecond)
	cancel()
	<-done
}
