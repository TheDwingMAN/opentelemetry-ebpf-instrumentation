// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package statagg

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ikube "go.opentelemetry.io/obi/pkg/internal/kube"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
)

// Pods and containers of the OpenShift-shaped lab (MicroShift 4.21, CRI-O,
// crun, systemd cgroup driver), from /sys/fs/cgroup/kubepods.slice there,
// and of the k3s lab (containerd).
const (
	burstablePod = "kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod73dc8baf_43a0_413e_aac2_5eb0868f6c1a.slice"
	burstableUID = "73dc8baf-43a0-413e-aac2-5eb0868f6c1a"
	burstableCtr = "f52987fbdcc7b29175fb52e01c7917e9d6d2e14550e3a2a7abf739da5a067e31"
	burstableBox = "c81572302e4a00c05810fc436ebc0952ed7a0806c58a2b7eddbfb58de4539206"

	bestEffortPod  = "kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod90b1ecb8_b850_451a_97c6_c073b5ddbb53.slice"
	bestEffortUID  = "90b1ecb8-b850-451a-97c6-c073b5ddbb53"
	bestEffortCtr  = "a1c299dc975032f1806601a8cb2fc7be0175969f6018956ade11dc989fbcd952"
	bestEffortCtr2 = "59db0b93ab678f22ad44e89bfc902a3a03e8aeec5e823f83e670919381cb20cd"

	// Guaranteed pods sit right under kubepods.slice (standard kubelet
	// naming; none ran on the lab).
	guaranteedPod = "kubepods.slice/kubepods-pod2d51509a_fcf0_41cc_b535_57cfeeaf73d1.slice"
	guaranteedUID = "2d51509a-fcf0-41cc-b535-57cfeeaf73d1"
	guaranteedCtr = "0853fad78812e955b92d871d8d597d9bc598e34320c9edbfab0a73eacf150145"

	containerdPod = "kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod6dc88073_2128_40d6_9dbc_0ba508da7fe8.slice"
	containerdUID = "6dc88073-2128-40d6-9dbc-0ba508da7fe8"
	containerdCtr = "123cd1db937c3c2d0d7772ef9b0a1c4b0b3dcfcb6b889452a90b2fcb43eae43a"
)

type cgroupFixture struct {
	path string
	want CgroupIdentity
}

var crioFixture = []cgroupFixture{
	{"kubepods.slice", CgroupIdentity{}},
	{"kubepods.slice/kubepods-burstable.slice", CgroupIdentity{}},
	{"kubepods.slice/kubepods-besteffort.slice", CgroupIdentity{}},
	{burstablePod, CgroupIdentity{PodUID: burstableUID}},
	{burstablePod + "/crio-" + burstableCtr + ".scope", CgroupIdentity{PodUID: burstableUID, ContainerID: burstableCtr}},
	{burstablePod + "/crio-" + burstableCtr + ".scope/container", CgroupIdentity{PodUID: burstableUID, ContainerID: burstableCtr}},
	{burstablePod + "/crio-conmon-" + burstableCtr + ".scope", CgroupIdentity{PodUID: burstableUID}},
	{burstablePod + "/crio-" + burstableBox, CgroupIdentity{PodUID: burstableUID}},
	{bestEffortPod, CgroupIdentity{PodUID: bestEffortUID}},
	{bestEffortPod + "/crio-" + bestEffortCtr + ".scope", CgroupIdentity{PodUID: bestEffortUID, ContainerID: bestEffortCtr}},
	{bestEffortPod + "/crio-" + bestEffortCtr + ".scope/container", CgroupIdentity{PodUID: bestEffortUID, ContainerID: bestEffortCtr}},
	{bestEffortPod + "/crio-conmon-" + bestEffortCtr + ".scope", CgroupIdentity{PodUID: bestEffortUID}},
	{bestEffortPod + "/crio-" + bestEffortCtr2, CgroupIdentity{PodUID: bestEffortUID}},
	{guaranteedPod, CgroupIdentity{PodUID: guaranteedUID}},
	{guaranteedPod + "/crio-" + guaranteedCtr + ".scope/container", CgroupIdentity{PodUID: guaranteedUID, ContainerID: guaranteedCtr}},
	{guaranteedPod + "/crio-conmon-" + guaranteedCtr + ".scope", CgroupIdentity{PodUID: guaranteedUID}},
	{containerdPod, CgroupIdentity{PodUID: containerdUID}},
	{containerdPod + "/cri-containerd-" + containerdCtr + ".scope", CgroupIdentity{PodUID: containerdUID, ContainerID: containerdCtr}},
}

// The cgroupfs driver (GKE's layout, as in the container package's cgroup
// formats): kubepods/<qos>/pod<uid>/<container id>.
var cgroupfsFixture = []cgroupFixture{
	{"kubepods", CgroupIdentity{}},
	{"kubepods/burstable", CgroupIdentity{}},
	{"kubepods/burstable/pod4a163a05-439d-484b-8e53-2968bc15824f", CgroupIdentity{PodUID: "4a163a05-439d-484b-8e53-2968bc15824f"}},
	{
		"kubepods/burstable/pod4a163a05-439d-484b-8e53-2968bc15824f/cde6dfaf5007ed65aad2d6aed72af91b0f3d95813492f773286e29ae145d20f4",
		CgroupIdentity{PodUID: "4a163a05-439d-484b-8e53-2968bc15824f", ContainerID: "cde6dfaf5007ed65aad2d6aed72af91b0f3d95813492f773286e29ae145d20f4"},
	},
	{"kubepods/podb53dfa9e2dc9b890f7fadb2770857b03", CgroupIdentity{PodUID: "b53dfa9e2dc9b890f7fadb2770857b03"}},
	{
		"kubepods/podb53dfa9e2dc9b890f7fadb2770857b03/crio-bb959773d06ad1a07d469bced637bbc49b6f8573c493fd0548d7f5810eb3e5a8",
		CgroupIdentity{PodUID: "b53dfa9e2dc9b890f7fadb2770857b03", ContainerID: "bb959773d06ad1a07d469bced637bbc49b6f8573c493fd0548d7f5810eb3e5a8"},
	},
}

// Cgroups outside kubepods that makeTree creates.
var outsideKubepods = []string{"system.slice", "system.slice/crio.service", "user.slice/user-1000.slice/session-3.scope"}

// makeTree creates the fixture's directories under a fresh root, plus
// system and user slices outside kubepods, and returns the root.
func makeTree(t *testing.T, fixture []cgroupFixture) string {
	t.Helper()
	root := t.TempDir()
	for _, f := range fixture {
		require.NoError(t, os.MkdirAll(filepath.Join(root, f.path), 0o755))
	}
	for _, dir := range outsideKubepods {
		require.NoError(t, os.MkdirAll(filepath.Join(root, dir), 0o755))
	}
	return root
}

// rescanAsked reports whether a lookup asked Run for a rescan, and takes
// the request.
func rescanAsked(x *CgroupIndex) bool {
	select {
	case <-x.rescan:
		return true
	default:
		return false
	}
}

func inoOf(t *testing.T, path string) uint64 {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)
	return info.Sys().(*syscall.Stat_t).Ino
}

// kind runs the kubelet with --cgroup-root=/kubelet: systemd driver, and
// the cgroupfs equivalent.
var kindFixture = []cgroupFixture{
	{"kubelet.slice", CgroupIdentity{}},
	{"kubelet.slice/kubelet-kubepods.slice", CgroupIdentity{}},
	{"kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice", CgroupIdentity{}},
	{
		"kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod" + strings.ReplaceAll(containerdUID, "-", "_") + ".slice",
		CgroupIdentity{PodUID: containerdUID},
	},
	{
		"kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod" + strings.ReplaceAll(containerdUID, "-", "_") + ".slice/cri-containerd-" + containerdCtr + ".scope",
		CgroupIdentity{PodUID: containerdUID, ContainerID: containerdCtr},
	},
	{
		"kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-pod" + strings.ReplaceAll(guaranteedUID, "-", "_") + ".slice",
		CgroupIdentity{PodUID: guaranteedUID},
	},
}

var kindCgroupfsFixture = []cgroupFixture{
	{"kubelet", CgroupIdentity{}},
	{"kubelet/kubepods", CgroupIdentity{}},
	{"kubelet/kubepods/burstable/pod" + burstableUID, CgroupIdentity{PodUID: burstableUID}},
	{"kubelet/kubepods/burstable/pod" + burstableUID + "/" + burstableCtr, CgroupIdentity{PodUID: burstableUID, ContainerID: burstableCtr}},
}

func TestCgroupIndex_EveryLevelResolves(t *testing.T) {
	for name, fixture := range map[string][]cgroupFixture{
		"crio-containerd-systemd": crioFixture, "cgroupfs": cgroupfsFixture,
		"kind-systemd": kindFixture, "kind-cgroupfs": kindCgroupfsFixture,
	} {
		t.Run(name, func(t *testing.T) {
			root := makeTree(t, fixture)
			x := NewCgroupIndex(WithCgroupRoots(root))
			require.NoError(t, x.Scan())
			for _, f := range fixture {
				got, final := x.Lookup(inoOf(t, filepath.Join(root, f.path)))
				assert.True(t, final, f.path)
				assert.Equal(t, f.want, got, f.path)
			}

			// Outside kubepods, and the root: known to have no pod,
			// without a rescan.
			for _, dir := range append([]string{"."}, outsideKubepods...) {
				got, final := x.Lookup(inoOf(t, filepath.Join(root, dir)))
				assert.True(t, final, dir)
				assert.Equal(t, CgroupIdentity{}, got, dir)
			}
			assert.False(t, rescanAsked(x), "no lookup asked for a rescan")
		})
	}
}

func TestCgroupIndex_RootAndNoCgroupNeedNoScan(t *testing.T) {
	x := NewCgroupIndex(WithCgroupRoots(t.TempDir()))
	for _, id := range []uint64{0, rootCgroupID} {
		got, final := x.Lookup(id)
		assert.True(t, final, "id %d", id)
		assert.Equal(t, CgroupIdentity{}, got)
	}
	assert.False(t, rescanAsked(x))
	assert.Empty(t, x.asked)
}

func TestCgroupIndex_FallsBackToTheHostRoot(t *testing.T) {
	// OBI's own cgroup namespace: a hierarchy without kubepods.
	own := makeTree(t, nil)
	root := makeTree(t, crioFixture)
	x := NewCgroupIndex(WithCgroupRoots(filepath.Join(t.TempDir(), "missing"), own, root))
	require.NoError(t, x.Scan())
	got, _ := x.Lookup(inoOf(t, filepath.Join(root, bestEffortPod)))
	assert.Equal(t, bestEffortUID, got.PodUID)
}

// A node without Kubernetes, or before the kubelet creates its cgroup:
// every scan completes, so unknown ids become final without a pod and stop
// asking for rescans, and a kubelet cgroup created later is found.
func TestCgroupIndex_NoKubepods(t *testing.T) {
	root := makeTree(t, nil)
	x := NewCgroupIndex(WithCgroupRoots(root))
	require.NoError(t, x.Scan())

	got, final := x.Lookup(inoOf(t, filepath.Join(root, "system.slice/crio.service")))
	assert.True(t, final, "walked although there is no kubepods")
	assert.Equal(t, CgroupIdentity{}, got)

	const unknown = 1 << 40
	_, final = x.Lookup(unknown)
	assert.False(t, final)
	require.True(t, rescanAsked(x))
	require.NoError(t, x.Scan())
	got, final = x.Lookup(unknown)
	assert.True(t, final, "the scan completed without kubepods: no pod")
	assert.Equal(t, CgroupIdentity{}, got)
	assert.False(t, rescanAsked(x), "and no more rescans")

	// The kubelet starts.
	for _, f := range crioFixture {
		require.NoError(t, os.MkdirAll(filepath.Join(root, f.path), 0o755))
	}
	require.NoError(t, x.Scan())
	got, final = x.Lookup(inoOf(t, filepath.Join(root, burstablePod)))
	assert.True(t, final)
	assert.Equal(t, burstableUID, got.PodUID)
}

func TestCgroupIndex_NoCgroupHierarchy(t *testing.T) {
	x := NewCgroupIndex(WithCgroupRoots(filepath.Join(t.TempDir(), "missing")))
	require.NoError(t, x.Scan(), "nothing to walk is a complete scan")
	_, final := x.Lookup(1 << 40)
	assert.False(t, final)
	require.NoError(t, x.Scan())
	_, final = x.Lookup(1 << 40)
	assert.True(t, final)
}

func TestCgroupIndex_TombstonesLastTenMinutes(t *testing.T) {
	root := makeTree(t, crioFixture)
	clock := newFakeClock()
	x := NewCgroupIndex(WithCgroupRoots(root), WithCgroupClock(clock.Now))
	require.NoError(t, x.Scan())

	scopeDir := filepath.Join(root, burstablePod, "crio-"+burstableCtr+".scope")
	leaf := inoOf(t, filepath.Join(scopeDir, "container"))
	podSlice := inoOf(t, filepath.Join(root, burstablePod))
	require.NoError(t, os.RemoveAll(scopeDir))
	clock.Advance(time.Second)
	require.NoError(t, x.Scan())

	got, final := x.Lookup(leaf)
	assert.True(t, final)
	assert.Equal(t, CgroupIdentity{PodUID: burstableUID, ContainerID: burstableCtr}, got,
		"a removed container keeps its pod and container")
	assert.True(t, x.Tombstoned(leaf))
	assert.False(t, x.Tombstoned(podSlice), "a live cgroup is no tombstone")

	clock.Advance(DefaultCgroupTombstoneTTL - 2*time.Second)
	require.NoError(t, x.Scan())
	assert.True(t, x.Tombstoned(leaf), "still within 10 minutes of the removal")

	clock.Advance(2 * time.Second)
	require.NoError(t, x.Scan())
	assert.False(t, x.Tombstoned(leaf))
	_, final = x.Lookup(leaf)
	assert.False(t, final, "forgotten: unknown until a rescan")
	require.True(t, rescanAsked(x))
	require.NoError(t, x.Scan())
	got, final = x.Lookup(leaf)
	assert.True(t, final)
	assert.Equal(t, CgroupIdentity{}, got, "an expired tombstone has no pod")
}

// Only a pod's cgroups hold their keys back: a removed cgroup outside
// kubepods has no labels to lose.
func TestCgroupIndex_NoTombstoneWithoutAPod(t *testing.T) {
	root := makeTree(t, crioFixture)
	x := NewCgroupIndex(WithCgroupRoots(root))
	require.NoError(t, x.Scan())
	service := filepath.Join(root, "system.slice/crio.service")
	qos := filepath.Join(root, "kubepods.slice/kubepods-besteffort.slice")
	ids := []uint64{inoOf(t, service), inoOf(t, qos)}
	require.NoError(t, os.Remove(service))
	require.NoError(t, os.RemoveAll(qos))
	require.NoError(t, x.Scan())
	for _, id := range ids {
		got, final := x.Lookup(id)
		assert.True(t, final)
		assert.Equal(t, CgroupIdentity{}, got)
		assert.False(t, x.Tombstoned(id))
	}
}

func TestCgroupIndex_UnknownIDAsksForARateLimitedRescan(t *testing.T) {
	root := makeTree(t, crioFixture)
	clock := newFakeClock()
	x := NewCgroupIndex(WithCgroupRoots(root), WithCgroupClock(clock.Now))
	require.NoError(t, x.Scan())
	require.Equal(t, 1, x.scans)

	newScope := func(ctr string) uint64 {
		dir := filepath.Join(root, bestEffortPod, "crio-"+ctr+".scope", "container")
		require.NoError(t, os.MkdirAll(dir, 0o755))
		return inoOf(t, dir)
	}
	first := newScope("1111111111111111111111111111111111111111111111111111111111111111")
	got, final := x.Lookup(first)
	assert.False(t, final, "created after the last scan: ask again later")
	assert.Equal(t, CgroupIdentity{}, got)
	assert.Equal(t, 1, x.scans, "the lookup did not scan")
	require.True(t, rescanAsked(x), "it asked Run for a rescan")

	second := newScope("2222222222222222222222222222222222222222222222222222222222222222")
	_, final = x.Lookup(second)
	assert.False(t, final)
	assert.False(t, rescanAsked(x), "within a second of the last request: no other")

	// Run's rescan.
	require.NoError(t, x.Scan())
	for id, ctr := range map[uint64]string{
		first:  "1111111111111111111111111111111111111111111111111111111111111111",
		second: "2222222222222222222222222222222222222222222222222222222222222222",
	} {
		got, final = x.Lookup(id)
		assert.True(t, final)
		assert.Equal(t, CgroupIdentity{PodUID: bestEffortUID, ContainerID: ctr}, got)
	}

	third := newScope("3333333333333333333333333333333333333333333333333333333333333333")
	clock.Advance(DefaultCgroupRescanInterval)
	_, final = x.Lookup(third)
	assert.False(t, final)
	assert.True(t, rescanAsked(x), "a second later: another request")
}

func TestCgroupIndex_NeverSeenID(t *testing.T) {
	root := makeTree(t, crioFixture)
	clock := newFakeClock()
	x := NewCgroupIndex(WithCgroupRoots(root), WithCgroupClock(clock.Now))
	require.NoError(t, x.Scan())

	// A cgroup that lived only between two scans.
	const gone = 1 << 40
	_, final := x.Lookup(gone)
	assert.False(t, final)
	require.True(t, rescanAsked(x))
	require.NoError(t, x.Scan())

	got, final := x.Lookup(gone)
	assert.True(t, final, "the rescan did not find it: final, without a pod")
	assert.Equal(t, CgroupIdentity{}, got)
	clock.Advance(time.Minute)
	_, final = x.Lookup(gone)
	assert.True(t, final)
	assert.False(t, rescanAsked(x), "an id known to be gone asks for no more rescans")
}

// A scan that started before the first lookup of an id may have read the
// hierarchy before the cgroup existed: only a later one makes it final.
func TestCgroupIndex_ScanRunningAtTheLookupIsNotEnough(t *testing.T) {
	root := makeTree(t, crioFixture)
	x := NewCgroupIndex(WithCgroupRoots(root))
	walking, release := make(chan struct{}), make(chan struct{})
	x.walk = func() (map[uint64]CgroupIdentity, error) {
		close(walking)
		<-release
		return x.walkRoots()
	}
	done := make(chan error)
	go func() { done <- x.Scan() }()
	<-walking

	const gone = 1 << 40
	_, final := x.Lookup(gone)
	assert.False(t, final)
	close(release)
	require.NoError(t, <-done)
	_, final = x.Lookup(gone)
	assert.False(t, final, "that scan started before the lookup")

	x.walk = x.walkRoots
	require.NoError(t, x.Scan())
	_, final = x.Lookup(gone)
	assert.True(t, final)
}

// Lookups run under a family's lock, which scrapes wait on: however long a
// walk takes, no lookup waits for it, and Run answers them once it is done.
func TestCgroupIndex_LookupNeverWaitsForAWalk(t *testing.T) {
	root := makeTree(t, crioFixture)
	x := NewCgroupIndex(WithCgroupRoots(root))
	leaf := inoOf(t, filepath.Join(root, bestEffortPod, "crio-"+bestEffortCtr+".scope/container"))
	var walks atomic.Int32
	release := make(chan struct{})
	x.walk = func() (map[uint64]CgroupIdentity, error) {
		walks.Add(1)
		<-release
		return x.walkRoots()
	}
	ctx, cancel := context.WithCancel(t.Context())
	ran := make(chan struct{})
	go func() { defer close(ran); x.Run(ctx) }()
	defer func() {
		cancel()
		// Run may be blocked in a walk.
		select {
		case <-release:
		default:
			close(release)
		}
		<-ran
	}()
	require.Eventually(t, func() bool { return walks.Load() == 1 }, 5*time.Second, time.Millisecond)

	lookups := make(chan struct{})
	go func() {
		defer close(lookups)
		for i := range 1000 {
			_, final := x.Lookup(leaf)
			assert.False(t, final, "the first scan is still walking")
			x.Lookup(uint64(1<<41 + i))
		}
	}()
	select {
	case <-lookups:
	case <-time.After(5 * time.Second):
		t.Fatal("a lookup waited for the walk")
	}

	close(release)
	require.Eventually(t, func() bool {
		got, final := x.Lookup(leaf)
		return final && got.ContainerID == bestEffortCtr
	}, 5*time.Second, time.Millisecond, "Run's scans answer the lookups")
}

// Step 21 deletes a cgroup's kernel keys only when they are idle and the
// cgroup's tombstone has expired, or the next I/O charged to the removed
// cgroup would create the key again without labels.
func TestCgroupIndex_KeysOutliveTombstones(t *testing.T) {
	root := makeTree(t, crioFixture)
	scopeDir := filepath.Join(root, bestEffortPod, "crio-"+bestEffortCtr+".scope")
	cgid := inoOf(t, filepath.Join(scopeDir, "container"))

	var index *CgroupIndex
	tf := newTestFamily(t, 1, diskBounds, func(c *Config) {
		c.Deletable = func(key []byte) bool {
			return !index.Tombstoned(uint64(binary.NativeEndian.Uint32(key)))
		}
	})
	index = NewCgroupIndex(WithCgroupRoots(root), WithCgroupClock(tf.clock.Now))
	require.NoError(t, index.Scan())
	p := tf.otelProducer(t, cumulative, 0)

	// The test key's dev field stands for the cgroup id.
	key := blkKey(uint32(cgid), 0, 0)
	record(tf.m, tf.layout, key, 0, 1, 1)
	produce(t, p)
	require.NoError(t, os.RemoveAll(scopeDir))
	require.NoError(t, index.Scan())

	for range 4 {
		tf.clock.Advance(time.Minute)
		produce(t, p)
	}
	assert.Contains(t, tf.m.entries, string(key), "idle, but tombstoned: kept")

	tf.clock.Advance(DefaultCgroupTombstoneTTL)
	require.NoError(t, index.Scan())
	produce(t, p)
	assert.NotContains(t, tf.m.entries, string(key), "tombstone expired: deleted")
}

type fakePodStore struct {
	byContainer map[string]*ikube.CachedObjMeta
	byUID       map[string]*ikube.CachedObjMeta
}

func (s fakePodStore) PodContainerByContainerID(id string) (*ikube.CachedObjMeta, string) {
	if m, ok := s.byContainer[id]; ok {
		return m, "app"
	}
	return nil, ""
}

func (s fakePodStore) PodByUID(uid string) *ikube.CachedObjMeta { return s.byUID[uid] }

func TestResolvePod(t *testing.T) {
	pod := &ikube.CachedObjMeta{Meta: &informer.ObjectMeta{Name: "io-xfs", Namespace: "default"}}
	store := fakePodStore{
		byContainer: map[string]*ikube.CachedObjMeta{bestEffortCtr: pod},
		byUID:       map[string]*ikube.CachedObjMeta{bestEffortUID: pod},
	}
	m, name := ResolvePod(store, CgroupIdentity{PodUID: bestEffortUID, ContainerID: bestEffortCtr})
	assert.Same(t, pod, m)
	assert.Equal(t, "app", name)

	m, name = ResolvePod(store, CgroupIdentity{PodUID: bestEffortUID, ContainerID: bestEffortCtr2})
	assert.Same(t, pod, m, "a container the store does not know yet resolves to its pod")
	assert.Empty(t, name)

	m, name = ResolvePod(store, CgroupIdentity{PodUID: bestEffortUID})
	assert.Same(t, pod, m, "conmon, sandbox and pod slice: pod only")
	assert.Empty(t, name)

	m, _ = ResolvePod(store, CgroupIdentity{})
	assert.Nil(t, m)
}

func TestCgroupIndex_ConcurrentLookupsAndScans(t *testing.T) {
	root := makeTree(t, crioFixture)
	x := NewCgroupIndex(WithCgroupRoots(root))
	require.NoError(t, x.Scan())
	leaf := inoOf(t, filepath.Join(root, bestEffortPod, "crio-"+bestEffortCtr+".scope/container"))

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 50 {
			assert.NoError(t, x.Scan())
		}
	}()
	for i := range 2000 {
		got, _ := x.Lookup(leaf)
		assert.Equal(t, bestEffortCtr, got.ContainerID)
		x.Lookup(uint64(1<<41 + i))
		x.Tombstoned(leaf)
	}
	<-done
}

// Under any other --cgroup-root the kubelet cgroup is not found: its pods'
// cgroups have no pod, like everything else.
func TestCgroupIndex_OtherCgroupRootsHaveNoPods(t *testing.T) {
	pod := "custom.slice/custom-kubepods.slice/custom-kubepods-pod" + strings.ReplaceAll(guaranteedUID, "-", "_") + ".slice"
	root := makeTree(t, []cgroupFixture{{pod, CgroupIdentity{}}})
	x := NewCgroupIndex(WithCgroupRoots(root))
	require.NoError(t, x.Scan())
	got, final := x.Lookup(inoOf(t, filepath.Join(root, pod)))
	assert.True(t, final)
	assert.Equal(t, CgroupIdentity{}, got)
}
