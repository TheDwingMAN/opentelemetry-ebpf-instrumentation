// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats // import "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"

import (
	"context"
	"fmt"
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
	mounts func() ([]*procfs.MountInfo, error)
	// deviceOf returns the device of a path of the host
	deviceOf func(path string) (major, minor uint32, err error)
	devices  *deviceNames
	interval time.Duration

	// reported are the volume devices of the previous resolution, to report the ones that are gone
	reported map[ebpf.PodVolume]bool
}

func NewPodVolumesTracer(store podVolumeSource, nodeName string) *PodVolumesTracer {
	return &PodVolumesTracer{
		store:    store,
		nodeName: nodeName,
		mounts:   func() ([]*procfs.MountInfo, error) { return procfs.GetProcMounts(1) },
		deviceOf: hostPathDevice,
		devices:  &deviceNames{sysRoot: "/sys"},
		interval: podVolumesInterval,
		reported: map[ebpf.PodVolume]bool{},
	}
}

func (p *PodVolumesTracer) TraceLoop(out *msg.Queue[[]*ebpf.Stat]) swarm.RunFunc {
	return func(ctx context.Context) {
		defer out.MarkCloseable()
		ticker := time.NewTicker(p.interval)
		defer ticker.Stop()
		for {
			if stats := p.readStats(); len(stats) > 0 {
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
		dtlog().Debug("can't read the mount table", "error", err)
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
		major, minor, err = p.deviceOf(pv.PersistentVolume.LocalPath)
		ok = err == nil
	}
	if !ok {
		return nil
	}
	dir := filepath.Join(p.devices.sysRoot, "dev", "block", fmt.Sprintf("%d:%d", major, minor))
	if !exists(dir) {
		// e.g. overlay, tmpfs or network filesystems, which are on no block device
		return nil
	}
	mounted := p.devices.name(major, minor)
	ownerName, ownerKind := pod.Name, pod.Kind
	if owner := ikube.TopOwner(pod.Pod); owner != nil {
		ownerName, ownerKind = owner.Name, owner.Kind
	}
	var volumes []ebpf.PodVolume
	for _, disk := range physicalDisks(dir, maxDeviceStackDepth) {
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

// physicalDisks returns the names of the disks that a block device is on, from its sysfs
// directory: the disk of a partition, or the disks below the slaves of a stacked device
func physicalDisks(dir string, depth int) []string {
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil || depth == 0 {
		return nil
	}
	if exists(filepath.Join(resolved, "partition")) {
		return physicalDisks(filepath.Dir(resolved), depth-1)
	}
	slaves, _ := filepath.Glob(filepath.Join(resolved, "slaves", "*"))
	if len(slaves) == 0 {
		return []string{filepath.Base(resolved)}
	}
	var disks []string
	for _, slave := range slaves {
		for _, disk := range physicalDisks(slave, depth-1) {
			if !slices.Contains(disks, disk) {
				disks = append(disks, disk)
			}
		}
	}
	return disks
}
