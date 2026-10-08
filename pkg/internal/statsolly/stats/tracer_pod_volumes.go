// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats // import "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"

import (
	"fmt"
	"path/filepath"
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

// podVolumesInterval is the time between two resolutions of the devices of the pod volumes
const podVolumesInterval = 30 * time.Second

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
	// mounts returns the mount table that has the volumes that the kubelet mounts
	mounts   func() ([]*procfs.MountInfo, error)
	devices  *deviceNames
	stack    *deviceStack
	interval time.Duration

	// reported are the volume devices of the previous resolution, to report the ones that are gone
	reported map[ebpf.PodVolume]bool
	// noKubeletMounts is set when a previous resolution found no mount of the kubelet, and warned
	noKubeletMounts bool
}

func NewPodVolumesTracer(store podVolumeSource, nodeName string, bioMeasured bool) *PodVolumesTracer {
	return &PodVolumesTracer{
		store:    store,
		nodeName: nodeName,
		mounts:   func() ([]*procfs.MountInfo, error) { return readHostMounts(procfs.DefaultMountPoint) },
		devices:  &deviceNames{sysRoot: "/sys", procRoot: "/proc"},
		stack:    newDeviceStack("/sys", bioMeasured),
		interval: podVolumesInterval,
		reported: map[ebpf.PodVolume]bool{},
	}
}

func (p *PodVolumesTracer) TraceLoop(out *msg.Queue[[]*ebpf.Stat]) swarm.RunFunc {
	return readEvery(p.interval, p.readStats, out)
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
	pods := p.store.PodsWithVolumeClaims(p.nodeName)
	p.warnWithoutKubeletMounts(mounts, len(pods) > 0)
	current := map[ebpf.PodVolume]bool{}
	var stats []*ebpf.Stat
	for _, pod := range pods {
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

// warnWithoutKubeletMounts warns, once until the mounts of the kubelet are visible again, that pods
// mount volumes while the mount table has no mount of the kubelet. Without such pods, it can't
// tell, so it keeps the state of the previous resolution.
func (p *PodVolumesTracer) warnWithoutKubeletMounts(mounts []*procfs.MountInfo, podsWithVolumes bool) {
	if !podsWithVolumes {
		return
	}
	missing := !hasKubeletVolumeMount(mounts)
	if missing && !p.noKubeletMounts {
		dtlog().Warn("no volume mount of the kubelet is visible: the devices of the pod volumes are not reported. "+
			"OBI needs the host PID namespace to read the mount table of the host, and, with OpenShift's mount "+
			"namespace encapsulation (kubens), CAP_SYS_PTRACE to find the mount namespace pinned at /"+kubensMount,
			"mounts", len(mounts))
	}
	p.noKubeletMounts = missing
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
