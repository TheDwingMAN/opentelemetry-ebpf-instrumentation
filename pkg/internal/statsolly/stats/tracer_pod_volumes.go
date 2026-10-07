// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats // import "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/prometheus/procfs"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	ikube "go.opentelemetry.io/obi/pkg/internal/kube"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

const (
	// podVolumesInterval is the time between two resolutions of the devices of the pod volumes
	podVolumesInterval = 30 * time.Second
	// maxDeviceStackDepth bounds the walk from a device to the disks below it, e.g. a partition
	// of an md RAID volume on LVM volumes on disk partitions
	maxDeviceStackDepth = 8
)

// podVolumeSource abstracts the Kubernetes metadata store
type podVolumeSource interface {
	PodsWithVolumeClaims(nodeName string) []*informer.ObjectMeta
	PersistentVolumeByClaim(namespace, claimName string) *informer.ObjectMeta
}

// PodVolumesTracer periodically resolves the volumes that the pods of the node mount from
// PersistentVolumeClaims into the block devices they are on, and forwards them as stats.
type PodVolumesTracer struct {
	store    podVolumeSource
	nodeName string
	// mounts returns the mount table of the host
	mounts   func() ([]*procfs.MountInfo, error)
	devices  *deviceNames
	stack    *deviceStack
	interval time.Duration

	// reported are the volume devices of the previous resolution, to report the ones that are gone
	reported map[ebpf.PodVolume]bool
}

func NewPodVolumesTracer(store podVolumeSource, nodeName string) *PodVolumesTracer {
	return &PodVolumesTracer{
		store:    store,
		nodeName: nodeName,
		mounts:   func() ([]*procfs.MountInfo, error) { return procfs.GetProcMounts(1) },
		devices:  &deviceNames{sysRoot: "/sys", procRoot: "/proc"},
		stack:    newDeviceStack("/sys"),
		interval: podVolumesInterval,
		reported: map[ebpf.PodVolume]bool{},
	}
}

func (p *PodVolumesTracer) TraceLoop(out *msg.Queue[[]*ebpf.Stat]) swarm.RunFunc {
	return readEvery(p.interval, p.readStats, out)
}

// readEvery forwards the stats that read returns now, and then every interval
func readEvery(interval time.Duration, read func() []*ebpf.Stat, out *msg.Queue[[]*ebpf.Stat]) swarm.RunFunc {
	return func(ctx context.Context) {
		defer out.MarkCloseable()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			if stats := read(); len(stats) > 0 {
				out.SendCtx(ctx, stats)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}
}

// readStats returns a stat of value 1 for each disk that each volume is on, and of value 0 for the
// ones that were reported before and are gone
func (p *PodVolumesTracer) readStats() []*ebpf.Stat {
	mounts, err := p.mounts()
	if err != nil {
		// without the mounts, the volumes would be reported as gone: the next read reports them
		dtlog().Debug("can't read the mount table", "error", err)
		return nil
	}
	current := map[ebpf.PodVolume]bool{}
	var stats []*ebpf.Stat
	for _, pod := range p.store.PodsWithVolumeClaims(p.nodeName) {
		for _, claim := range pod.Pod.VolumeClaims {
			for _, volume := range p.volumeDevices(pod, claim, mounts) {
				current[volume] = true
				stats = append(stats, podVolumeStat(volume, 1))
			}
		}
	}
	for volume := range p.reported {
		if !current[volume] {
			stats = append(stats, podVolumeStat(volume, 0))
		}
	}
	p.reported = current
	return stats
}

// volumeDevices resolves a volume of a pod into one PodVolume per disk that it is on
func (p *PodVolumesTracer) volumeDevices(pod *informer.ObjectMeta, claim *informer.VolumeClaim, mounts []*procfs.MountInfo) []ebpf.PodVolume {
	pv := p.store.PersistentVolumeByClaim(pod.Namespace, claim.ClaimName)
	if pv == nil {
		return nil
	}
	major, minor, ok := volumeMountDevice(mounts, pod.Pod.Uid, pv.Name)
	if !ok && pv.GetPersistentVolume().GetLocalPath() != "" {
		var err error
		major, minor, err = p.stack.deviceOf(pv.PersistentVolume.LocalPath)
		ok = err == nil
	}
	if !ok {
		return nil
	}
	dir, ok := p.stack.blockDeviceDir(major, minor)
	if !ok {
		return nil
	}
	mounted := p.devices.name(major, minor)
	ownerName, ownerKind := pod.Name, pod.Kind
	if owner := ikube.TopOwner(pod.Pod); owner != nil {
		ownerName, ownerKind = owner.Name, owner.Kind
	}
	var volumes []ebpf.PodVolume
	for _, disk := range p.stack.physicalDisks(dir, maxDeviceStackDepth) {
		volumes = append(volumes, ebpf.PodVolume{
			Namespace:        pod.Namespace,
			PodName:          pod.Name,
			OwnerName:        ownerName,
			OwnerKind:        ownerKind,
			VolumeName:       claim.VolumeName,
			ClaimName:        claim.ClaimName,
			PersistentVolume: pv.Name,
			MountedDevice:    mounted,
			Device:           disk,
		})
	}
	return volumes
}

// podVolumeStat reports a volume device with the pod metadata that the Kubernetes decorator would
// add from a container
func podVolumeStat(volume ebpf.PodVolume, value int64) *ebpf.Stat {
	volume.Value = value
	stat := &ebpf.Stat{Type: ebpf.StatTypePodVolume, PodVolume: &volume}
	stat.CommonAttrs.Metadata = map[attr.Name]string{
		attr.K8sNamespaceName: volume.Namespace,
		attr.K8sPodName:       volume.PodName,
		attr.K8sOwnerName:     volume.OwnerName,
		attr.K8sKind:          volume.OwnerKind,
	}
	return stat
}

// volumeMountDevice finds the device of a PersistentVolume of a pod from where the kubelet mounts
// it: <kubelet root>/pods/<pod UID>/volumes/<plugin>/<PersistentVolume>, followed by /mount for
// CSI volumes
func volumeMountDevice(mounts []*procfs.MountInfo, podUID, pvName string) (major, minor uint32, ok bool) {
	podVolumes := "/pods/" + podUID + "/volumes/"
	for _, m := range mounts {
		if !strings.Contains(m.MountPoint, podVolumes) {
			continue
		}
		mountPoint := strings.TrimSuffix(m.MountPoint, "/mount")
		if filepath.Base(mountPoint) != pvName {
			continue
		}
		if _, err := fmt.Sscanf(m.MajorMinorVer, "%d:%d", &major, &minor); err == nil {
			return major, minor, true
		}
	}
	return 0, 0, false
}

// deviceStack walks sysfs from the block devices of the host to the disks below them
type deviceStack struct {
	sysRoot string
	// deviceOf returns the device of a path of the host
	deviceOf func(path string) (major, minor uint32, err error)
}

func newDeviceStack(sysRoot string) *deviceStack {
	return &deviceStack{sysRoot: sysRoot, deviceOf: hostPathDevice}
}

// blockDeviceDir returns the sysfs directory of a block device, and false for the devices of the
// filesystems on no block device, like overlay, tmpfs or network filesystems
func (s *deviceStack) blockDeviceDir(major, minor uint32) (string, bool) {
	dir := filepath.Join(s.sysRoot, "dev", "block", fmt.Sprintf("%d:%d", major, minor))
	return dir, exists(dir)
}

// physicalDisks returns the names of the disks that a block device is on, from its sysfs
// directory: the disk of a partition, the disks of the filesystem that holds the file of a loop
// device, or the disks below the slaves of a stacked device
func (s *deviceStack) physicalDisks(dir string, depth int) []string {
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil || depth == 0 {
		return nil
	}
	if exists(filepath.Join(resolved, "partition")) {
		return s.physicalDisks(filepath.Dir(resolved), depth-1)
	}
	if backing, ok := s.loopBackingDevice(resolved); ok {
		return s.physicalDisks(backing, depth-1)
	}
	slaves, _ := filepath.Glob(filepath.Join(resolved, "slaves", "*"))
	if len(slaves) == 0 {
		return []string{filepath.Base(resolved)}
	}
	var disks []string
	for _, slave := range slaves {
		for _, disk := range s.physicalDisks(slave, depth-1) {
			if !slices.Contains(disks, disk) {
				disks = append(disks, disk)
			}
		}
	}
	return disks
}

// loopBackingDevice returns the sysfs directory of the block device of the filesystem that holds
// the file of a loop device, which it finds by its path on the host. It returns false for other
// devices, and when the file was deleted, isn't at that path on the host (e.g. a loop device set
// up in the mount namespace of a container), or is on no block device.
func (s *deviceStack) loopBackingDevice(dir string) (string, bool) {
	content, err := os.ReadFile(filepath.Join(dir, "loop", "backing_file"))
	if err != nil {
		return "", false
	}
	// the kernel appends " (deleted)" to the path of a deleted file
	path, deleted := strings.CutSuffix(strings.TrimSuffix(string(content), "\n"), " (deleted)")
	if deleted {
		return "", false
	}
	major, minor, err := s.deviceOf(path)
	if err != nil {
		return "", false
	}
	return s.blockDeviceDir(major, minor)
}
