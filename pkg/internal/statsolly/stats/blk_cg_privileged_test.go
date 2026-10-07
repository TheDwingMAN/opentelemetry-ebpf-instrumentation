// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package stats

import (
	"bufio"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	ikube "go.opentelemetry.io/obi/pkg/internal/kube"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
)

const (
	envPodWriterDevice = "OBI_TEST_POD_WRITER_DEVICE"
	envPodWriterBlocks = "OBI_TEST_POD_WRITER_BLOCKS"
	envPodWriterOffset = "OBI_TEST_POD_WRITER_OFFSET"
)

// The pods of the test, laid out as CRI-O with the systemd cgroup driver lays
// them out (S0-d): pod A runs container "writer", whose processes live in
// the /container leaf of its scope, and the conmon scope that writes its
// logs; pod C's container is removed once it has written, as on a restart.
var (
	podAUID = "6a1f0c2e-3b4d-4e5f-8a9b-0c1d2e3f4a01"
	podCUID = "6a1f0c2e-3b4d-4e5f-8a9b-0c1d2e3f4c03"
	ctrA    = strings.Repeat("a1", 32)
	ctrC    = strings.Repeat("c3", 32)
)

// TestBlockPodCountersPerCgroup loads the block programs with
// storage_block_pod, writes to a loop device from child processes in a
// CRI-O-like cgroup tree, resolves the cgroups with the step 5 cgroup index,
// and checks that each pod, container and the no-pod remainder are charged
// exactly the writes their processes made, and that together they are the
// device's diskstats. Scaffolding from v2 (tracer_disk_privileged_test.go
// ioCgroupRoot, runInCgroup, child writers), without writing the host's
// root subtree_control, extended with the /container leaf, a conmon scope
// and a removed container cgroup.
func TestBlockPodCountersPerCgroup(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load eBPF programs, set up block devices and cgroups")
	}
	parent := ioCgroupParent(t)
	tree := newIOCgroupTree(t, parent)
	qos := tree.mkdir("kubepods.slice", "kubepods-besteffort.slice")
	podA := tree.mkdir(qos, "kubepods-besteffort-pod"+strings.ReplaceAll(podAUID, "-", "_")+".slice")
	leafA := tree.mkdir(podA, "crio-"+ctrA+".scope", "container")
	conmonA := tree.mkdir(podA, "crio-conmon-"+ctrA+".scope")
	podC := tree.mkdir(qos, "kubepods-besteffort-pod"+strings.ReplaceAll(podCUID, "-", "_")+".slice")
	scopeC := tree.mkdir(podC, "crio-"+ctrC+".scope")
	leafC := tree.mkdir(scopeC, "container")
	service := tree.mkdir("system.slice", "obi-test.service")

	layout, err := statagg.NewExplicitLayout(export.DefaultBuckets.StatDiskOperationDurationHistogram)
	require.NoError(t, err)
	features := export.FeatureStorageBlockIo | export.FeatureStorageBlockPod
	fetcher, err := ebpf.NewStatsFetcher(&config.EBPFTracer{StorageAggregation: config.StorageAggregation{BlockPodMapsBudgetBytes: 8 << 20}},
		&features, &attributes.SelectorConfig{}, ebpf.FsAggregation{}, ebpf.NFSConfig{},
		&ebpf.BlockAggregation{BoundsNs: layout.KernelBounds(), BudgetBytes: 8 << 20}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { fetcher.Close() })
	maps := fetcher.BlockAggregation()
	require.NotNil(t, maps)
	require.NotNil(t, maps.Cgroup, "storage_block_pod counts in blk_cg_agg")

	index := statagg.NewCgroupIndex(statagg.WithCgroupRoots(parent))
	require.NoError(t, index.Scan())
	store := podStore{
		uids: map[string]*ikube.CachedObjMeta{podAUID: testPod("writer-a", podAUID), podCUID: testPod("writer-c", podCUID)},
		containers: map[string]podContainer{
			ctrA: {podAUID, "writer"},
			ctrC: {podCUID, "restarted"},
		},
	}
	pods := NewBlockPodResolver(index, store)
	src, err := statagg.NewMapSource(maps.Cgroup)
	require.NoError(t, err)
	family, err := BlockCgroupFamily(src, features, pods, func(*ebpf.Stat) bool { return true })
	require.NoError(t, err)
	registry, err := statagg.NewRegistry(family)
	require.NoError(t, err)
	selection := attributes.Selection{"obi.stat.disk.*": attributes.InclusionLists{Include: []string{
		"system.device", "disk.io.direction", "k8s.pod.name", "k8s.container.name",
	}}}
	selection.Normalize()
	selector, err := attributes.NewAttrSelector(attributes.GroupKubernetes|attributes.GroupStatsBlockPod,
		&attributes.SelectorConfig{SelectionCfg: selection})
	require.NoError(t, err)
	collector := statagg.NewCollector(registry, time.Hour)
	for _, m := range []attributes.Name{attributes.StatDiskOperations, attributes.StatDiskOperationTime, attributes.StatDiskIO} {
		getters := attributes.PrometheusGetters(ebpf.StatStringGetters, selector.For(m))
		names := make([]string, len(getters))
		for i, g := range getters {
			names[i] = g.ExposedName
		}
		require.NoError(t, collector.Add(m, statagg.PromMetric{
			Help: "h", LabelNames: names,
			Project: func(s *ebpf.Stat) (string, []string) {
				v := make([]string, len(getters))
				for i, g := range getters {
					v[i] = g.Get(s)
				}
				return statagg.SeriesKey(v), v
			},
		}))
	}
	reg := prometheus.NewPedanticRegistry()
	require.NoError(t, reg.Register(collector))
	go family.Run(t.Context())

	_, path, stat := loopDevice(t)
	name := filepath.Base(path)
	before := waitIdle(t, stat)
	start := time.Now()
	writers := []struct {
		cgroup        string
		blocks, first int
	}{
		{leafA, 64, 0},
		{conmonA, 32, 64},
		{leafC, 16, 96},
		{service, 8, 112},
	}
	for _, w := range writers {
		runInCgroup(t, w.cgroup, "TestBlockPodWriterProcess", envPodWriterDevice+"="+path,
			envPodWriterBlocks+"="+strconv.Itoa(w.blocks), envPodWriterOffset+"="+strconv.Itoa(w.first))
	}
	elapsed := time.Since(start)
	after := waitIdle(t, stat)

	// Pod C's container is removed after its writes, as on a restart: its
	// cgroups become tombstones, which still resolve.
	cgroupC := dirIno(t, leafC)
	tree.remove(leafC)
	tree.remove(scopeC)
	require.NoError(t, index.Scan())
	assert.True(t, index.Tombstoned(cgroupC))
	assert.False(t, pods.deletable(cgKey(cgroupC, 0, 0, ebpf.CodeBlockWrite)),
		"a removed pod cgroup's keys stay while its tombstone lasts")

	time.Sleep(1100 * time.Millisecond) // a family reads its map at most once a second
	mfs, err := reg.Gather()
	require.NoError(t, err)
	series := func(metric, pod, container string) *dto.Metric {
		for _, m := range podSeriesOf(mfs, metric, name, "write") {
			if m.labels["k8s_pod_name"] == pod && m.labels["k8s_container_name"] == container {
				return m.metric
			}
		}
		return nil
	}
	ops := attributes.StatDiskOperations.Prom
	for _, c := range []struct {
		pod, container string
		blocks         float64
	}{
		{"writer-a", "writer", 64},
		{"writer-a", "", 32}, // conmon: the pod, no container
		{"writer-c", "restarted", 16},
	} {
		m := series(ops, c.pod, c.container)
		require.NotNil(t, m, "%s/%s", c.pod, c.container)
		assert.InDelta(t, c.blocks, m.GetCounter().GetValue(), 0, "%s/%s writes", c.pod, c.container)
		io := series(attributes.StatDiskIO.Prom, c.pod, c.container)
		require.NotNil(t, io)
		assert.InDelta(t, c.blocks*aggTestBlock, io.GetCounter().GetValue(), 0, "%s/%s bytes", c.pod, c.container)
		opTime := series(attributes.StatDiskOperationTime.Prom, c.pod, c.container)
		require.NotNil(t, opTime)
		assert.Positive(t, opTime.GetCounter().GetValue())
		assert.Less(t, opTime.GetCounter().GetValue(), elapsed.Seconds(), "a write's time is within the writers' run")
	}
	noPod := series(ops, "", "")
	require.NotNil(t, noPod, "the I/O of a cgroup outside kubepods is a series without pod attributes")
	assert.InDelta(t, 8, noPod.GetCounter().GetValue(), 0)

	// /sys/block/<dev>/stat, 0-based: 4 writes, 15 flushes. Direct writes
	// without fsync: no flush.
	var writes float64
	for _, m := range podSeriesOf(mfs, ops, name, "write") {
		writes += m.metric.GetCounter().GetValue()
	}
	assert.InDelta(t, float64(after[4]-before[4]-(after[15]-before[15])), writes, 0,
		"the pod series and the remainder add up to the device's writes")
}

// TestBlockPodWritebackChargedToTheFileOwner writes a new file, buffered and
// without syncing it, from a child process in a pod's container cgroup, and
// syncs it from this process, outside any pod: the data is issued by this
// process (or a flusher thread, in the root cgroup), never by the writer,
// yet charged to the writer's container, the owner of the file's writeback
// domain (S0-d). The cgroup is never taken from the task that issues the
// request.
func TestBlockPodWritebackChargedToTheFileOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load eBPF programs, set up block devices and cgroups")
	}
	mkfs, err := exec.LookPath("mkfs.ext4")
	if err != nil {
		t.Skip("no mkfs.ext4")
	}
	parent := ioCgroupParent(t)
	if !enableController(parent, "memory") {
		t.Skip("cgroup writeback needs the memory controller next to io")
	}
	tree := newIOCgroupTree(t, parent)
	tree.controllers = "+io +memory"
	podA := tree.mkdir("kubepods.slice", "kubepods-besteffort.slice",
		"kubepods-besteffort-pod"+strings.ReplaceAll(podAUID, "-", "_")+".slice")
	leafA := tree.mkdir(podA, "crio-"+ctrA+".scope", "container")

	features := export.FeatureStorageBlockIo | export.FeatureStorageBlockPod
	fetcher, err := ebpf.NewStatsFetcher(&config.EBPFTracer{StorageAggregation: config.StorageAggregation{BlockPodMapsBudgetBytes: 8 << 20}},
		&features, &attributes.SelectorConfig{}, ebpf.FsAggregation{}, ebpf.NFSConfig{}, nil, nil)
	require.NoError(t, err)
	t.Cleanup(func() { fetcher.Close() })
	maps := fetcher.BlockAggregation()
	require.NotNil(t, maps)
	require.NotNil(t, maps.Cgroup)

	dev, path, stat := loopDeviceOfSize(t, 64<<20)
	out, err := exec.Command(mkfs, "-q", "-F", path).CombinedOutput()
	require.NoError(t, err, string(out))
	mnt := t.TempDir()
	require.NoError(t, unix.Mount(path, mnt, "ext4", 0, ""))
	t.Cleanup(func() { _ = unix.Unmount(mnt, unix.MNT_DETACH) })
	waitIdle(t, stat)

	src, err := statagg.NewMapSource(maps.Cgroup)
	require.NoError(t, err)
	base := writeBytesByCgroup(t, src, dev)

	const fileBytes = 4 << 20
	file := filepath.Join(mnt, "owned-by-the-writer")
	runInCgroup(t, leafA, "TestBlockPodBufferedWriterProcess", envPodWriterFile+"="+file,
		envPodWriterBlocks+"="+strconv.Itoa(fileBytes/aggTestBlock))
	f, err := os.Open(file)
	require.NoError(t, err)
	require.NoError(t, unix.Syncfs(int(f.Fd())))
	f.Close()
	waitIdle(t, stat)

	got := writeBytesByCgroup(t, src, dev)
	writer, syncer := dirIno(t, leafA), ownCgroup(t)
	assert.GreaterOrEqual(t, got[writer]-base[writer], uint64(fileBytes),
		"the file's data is charged to the cgroup that wrote it")
	assert.Less(t, got[syncer]-base[syncer], uint64(fileBytes),
		"not to the process that synced it: at most its own metadata")
}

const envPodWriterFile = "OBI_TEST_POD_WRITER_FILE"

// TestBlockPodBufferedWriterProcess is not a test:
// TestBlockPodWritebackChargedToTheFileOwner runs it as a child process that
// creates a file and writes it through the page cache, without syncing it.
func TestBlockPodBufferedWriterProcess(t *testing.T) {
	file := os.Getenv(envPodWriterFile)
	if file == "" {
		t.Skip("only runs as a child process of TestBlockPodWritebackChargedToTheFileOwner")
	}
	blocks, err := strconv.Atoi(os.Getenv(envPodWriterBlocks))
	require.NoError(t, err)
	_, err = bufio.NewReader(os.Stdin).ReadString('\n')
	require.NoError(t, err)

	f, err := os.Create(file)
	require.NoError(t, err)
	defer f.Close()
	buf := make([]byte, aggTestBlock)
	for i := range buf {
		buf[i] = byte(i)
	}
	for range blocks {
		_, err := f.Write(buf)
		require.NoError(t, err)
	}
}

// writeBytesByCgroup sums blk_cg_agg's write bytes for dev per cgroup.
func writeBytesByCgroup(t *testing.T, src *statagg.MapSource, dev uint32) map[uint64]uint64 {
	t.Helper()
	out := map[uint64]uint64{}
	require.NoError(t, src.ForEach(func(key, values []byte) {
		if binary.NativeEndian.Uint32(key[cgKeyDev:]) != dev || key[cgKeyKind] != byte(ebpf.CodeBlockWrite) {
			return
		}
		cgid := binary.NativeEndian.Uint64(key[cgKeyCgid:])
		for cpu := range src.CPUs() {
			out[cgid] += binary.NativeEndian.Uint64(values[cpu*src.ValueStride()+cgWordBytes*8:])
		}
	}))
	return out
}

// ownCgroup is this process's cgroup v2 id: the inode of its directory.
func ownCgroup(t *testing.T) uint64 {
	t.Helper()
	raw, err := os.ReadFile("/proc/self/cgroup")
	require.NoError(t, err)
	for line := range strings.SplitSeq(strings.TrimSpace(string(raw)), "\n") {
		if path, ok := strings.CutPrefix(line, "0::"); ok {
			return dirIno(t, filepath.Join("/sys/fs/cgroup", path))
		}
	}
	t.Fatal("no cgroup v2 path for this process")
	return 0
}

// enableController enables controller for the children of cgroup, reporting
// whether it could.
func enableController(cgroup, controller string) bool {
	return os.WriteFile(filepath.Join(cgroup, "cgroup.subtree_control"), []byte("+"+controller), 0o644) == nil
}

// TestBlockPodWriterProcess is not a test: TestBlockPodCountersPerCgroup runs
// it as a child process that writes blocks to a device with O_DIRECT once
// its parent has moved it to a cgroup and tells it to start.
func TestBlockPodWriterProcess(t *testing.T) {
	device := os.Getenv(envPodWriterDevice)
	if device == "" {
		t.Skip("only runs as a child process of TestBlockPodCountersPerCgroup")
	}
	blocks, err := strconv.Atoi(os.Getenv(envPodWriterBlocks))
	require.NoError(t, err)
	first, err := strconv.Atoi(os.Getenv(envPodWriterOffset))
	require.NoError(t, err)
	_, err = bufio.NewReader(os.Stdin).ReadString('\n')
	require.NoError(t, err)

	f, err := os.OpenFile(device, os.O_WRONLY|unix.O_DIRECT, 0)
	require.NoError(t, err)
	defer f.Close()
	buf := alignedBlock(t)
	for i := range blocks {
		_, err := f.WriteAt(buf, int64((first+i)*aggTestBlock))
		require.NoError(t, err)
	}
}

type podSeries struct {
	labels map[string]string
	metric *dto.Metric
}

func podSeriesOf(mfs []*dto.MetricFamily, name, device, direction string) []podSeries {
	var out []podSeries
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			if labels["system_device"] == device && labels["disk_io_direction"] == direction {
				out = append(out, podSeries{labels: labels, metric: m})
			}
		}
	}
	return out
}

// ioCgroupParent returns a cgroup of the test's own with the io controller
// enabled for its children, removed after the test. It never changes the
// host's root cgroup: in a container with its own cgroup namespace (the
// privileged test containers), it enables io on the namespace's root after
// moving that root's processes to a leaf, which cgroup v2 requires
// (no internal processes); on a host, io must already be enabled in the
// root's subtree_control. Cgroup v1 and an io controller that is not
// available skip the test, as storage_block_pod is disabled there.
func ioCgroupParent(t *testing.T) string {
	t.Helper()
	const root = "/sys/fs/cgroup"
	controllers, err := os.ReadFile(filepath.Join(root, "cgroup.controllers"))
	if err != nil {
		t.Skip("no cgroup v2 hierarchy: storage_block_pod needs one")
	}
	if !slices.Contains(strings.Fields(string(controllers)), "io") {
		t.Skip("the cgroup v2 io controller is not available")
	}
	if !subtreeHasIO(root) {
		if _, err := os.Stat(filepath.Join(root, "cgroup.type")); err != nil {
			t.Skip("io is not enabled in the host's root cgroup.subtree_control, which this test does not change")
		}
		procs := filepath.Join(root, "obi-test-procs")
		require.NoError(t, os.MkdirAll(procs, 0o755))
		raw, err := os.ReadFile(filepath.Join(root, "cgroup.procs"))
		require.NoError(t, err)
		for _, pid := range strings.Fields(string(raw)) {
			_ = os.WriteFile(filepath.Join(procs, "cgroup.procs"), []byte(pid), 0o644)
		}
		if err := os.WriteFile(filepath.Join(root, "cgroup.subtree_control"), []byte("+io"), 0o644); err != nil {
			t.Skipf("can't enable io for this container's cgroups: %v", err)
		}
		// For cgroup writeback, which needs memory next to io; best effort.
		_ = enableController(root, "memory")
	}
	parent := filepath.Join(root, "obi-test-pods-"+strconv.Itoa(os.Getpid()))
	require.NoError(t, os.Mkdir(parent, 0o755))
	t.Cleanup(func() { _ = os.Remove(parent) })
	require.NoError(t, os.WriteFile(filepath.Join(parent, "cgroup.subtree_control"), []byte("+io"), 0o644))
	return parent
}

func subtreeHasIO(cgroup string) bool {
	raw, err := os.ReadFile(filepath.Join(cgroup, "cgroup.subtree_control"))
	return err == nil && slices.Contains(strings.Fields(string(raw)), "io")
}

// ioCgroupTree creates cgroups under a parent, each with io enabled for its
// children, so that every leaf has an io controller of its own (as the
// kubelet and CRI-O delegate it down to the /container leaves, S0-d), and
// removes them deepest first.
type ioCgroupTree struct {
	t       *testing.T
	parent  string
	created []string
	// controllers are enabled for the children of every directory created.
	controllers string
}

func newIOCgroupTree(t *testing.T, parent string) *ioCgroupTree {
	tree := &ioCgroupTree{t: t, parent: parent, controllers: "+io"}
	t.Cleanup(func() {
		for i := len(tree.created) - 1; i >= 0; i-- {
			_ = os.Remove(tree.created[i])
		}
	})
	return tree
}

// mkdir creates the path of directories below parent (or below the first
// element when it is absolute), enabling io in each, and returns the last.
func (c *ioCgroupTree) mkdir(names ...string) string {
	c.t.Helper()
	dir := c.parent
	if filepath.IsAbs(names[0]) {
		dir, names = names[0], names[1:]
	}
	for _, name := range names {
		dir = filepath.Join(dir, name)
		if _, err := os.Stat(dir); err != nil {
			require.NoError(c.t, os.Mkdir(dir, 0o755))
			c.created = append(c.created, dir)
		}
		// A leaf that gets processes can't have controllers enabled for
		// children; enabling them on an empty directory is fine either way.
		_ = os.WriteFile(filepath.Join(dir, "cgroup.subtree_control"), []byte(c.controllers), 0o644)
	}
	return dir
}

func (c *ioCgroupTree) remove(dir string) {
	c.t.Helper()
	require.NoError(c.t, os.Remove(dir))
}

// dirIno is a cgroup's id: its directory inode, as the cgroup index keys it.
func dirIno(t *testing.T, dir string) uint64 {
	t.Helper()
	var st unix.Stat_t
	require.NoError(t, unix.Stat(dir, &st))
	return st.Ino
}

// runInCgroup runs the given test of this binary as a child process in
// cgroup, with the given environment, and waits for it.
func runInCgroup(t *testing.T, cgroup, testName string, env ...string) {
	t.Helper()
	// The writer's process goes in a leaf: no controller may be enabled for
	// the children of a cgroup with processes.
	_ = os.WriteFile(filepath.Join(cgroup, "cgroup.subtree_control"), []byte("-io -memory"), 0o644)

	cmd := exec.Command(os.Args[0], "-test.run=^"+testName+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	start, err := cmd.StdinPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())

	require.NoError(t, os.WriteFile(filepath.Join(cgroup, "cgroup.procs"), []byte(strconv.Itoa(cmd.Process.Pid)), 0o644))
	_, err = start.Write([]byte("start\n"))
	require.NoError(t, err)
	require.NoError(t, cmd.Wait())
}

// podStore is the Kubernetes store's view of the test's pods.
type podStore struct {
	uids       map[string]*ikube.CachedObjMeta
	containers map[string]podContainer
}

type podContainer struct{ podUID, name string }

func (s podStore) PodContainerByContainerID(id string) (*ikube.CachedObjMeta, string) {
	c, ok := s.containers[id]
	if !ok {
		return nil, ""
	}
	return s.uids[c.podUID], c.name
}

func (s podStore) PodByUID(uid string) *ikube.CachedObjMeta { return s.uids[uid] }

func testPod(name, uid string) *ikube.CachedObjMeta {
	pod := ioXfsPod()
	pod.Meta.Name, pod.Meta.Pod.Uid = name, uid
	return pod
}
