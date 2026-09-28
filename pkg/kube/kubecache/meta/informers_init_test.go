// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package meta

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
)

type eventObserver struct {
	id     string
	events []*informer.Event
}

func (o *eventObserver) ID() string {
	return o.id
}

func (o *eventObserver) On(event *informer.Event) error {
	o.events = append(o.events, event)
	return nil
}

func TestEnvironmentFiltering(t *testing.T) {
	vars := []v1.EnvVar{{Name: "A", Value: "B"}, {Value: "C"}, {}, {Name: "OTEL_SERVICE_NAME", Value: "service_name"}, {Name: "OTEL_RESOURCE_ATTRIBUTES", Value: "resource_attributes"}}

	filtered := envToMap(nil, metav1.ObjectMeta{}, vars)
	assert.Len(t, filtered, 2)

	serviceName, ok := filtered["OTEL_SERVICE_NAME"]
	assert.True(t, ok)
	assert.Equal(t, "service_name", serviceName)

	resourceAttrs, ok := filtered["OTEL_RESOURCE_ATTRIBUTES"]
	assert.True(t, ok)
	assert.Equal(t, "resource_attributes", resourceAttrs)
}

func testUnchangedImpl(t *testing.T, o1, o2 *informer.ObjectMeta, expected bool) {
	assert.Equal(t, expected, unchanged(o1, o2))
}

func TestUnchanged(t *testing.T) {
	type testData struct {
		name           string
		o1             informer.ObjectMeta
		o2             informer.ObjectMeta
		expectedResult bool
	}

	data := []testData{
		{
			"empty",
			informer.ObjectMeta{},
			informer.ObjectMeta{},
			true,
		},
		{
			"name",
			informer.ObjectMeta{
				Name: "meta",
			},
			informer.ObjectMeta{},
			true,
		},
		{
			"namespace",
			informer.ObjectMeta{
				Namespace: "default",
			},
			informer.ObjectMeta{},
			true,
		},
		{
			"labels",
			informer.ObjectMeta{
				Labels: map[string]string{"foo": "bar"},
			},
			informer.ObjectMeta{},
			false,
		},
		{
			"annotations",
			informer.ObjectMeta{
				Annotations: map[string]string{"foo": "bar"},
			},
			informer.ObjectMeta{},
			false,
		},
		{
			"nilpod",
			informer.ObjectMeta{
				Pod: nil,
			},
			informer.ObjectMeta{
				Pod: nil,
			},
			true,
		},
		{
			"zeropod",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{},
			},
			informer.ObjectMeta{
				Pod: nil,
			},
			false,
		},
		{
			"emptypod",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{},
			},
			informer.ObjectMeta{
				Pod: &informer.PodInfo{},
			},
			true,
		},
		{
			"pod_uid",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Uid: "uid",
				},
			},
			informer.ObjectMeta{
				Pod: &informer.PodInfo{},
			},
			false,
		},
		{
			"pod_uid_eq",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Uid: "uid",
				},
			},
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Uid: "uid",
				},
			},
			true,
		},
		{
			"pod_nodename",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					NodeName: "abacaxi",
				},
			},
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					NodeName: "jabuticaba",
				},
			},
			false,
		},
		{
			"pod_nodename_eq",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					NodeName: "abacaxi",
				},
			},
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					NodeName: "abacaxi",
				},
			},
			true,
		},
		{
			"pod_startttime",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					StartTimeStr: "12345",
				},
			},
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					StartTimeStr: "7890",
				},
			},
			false,
		},
		{
			"pod_startttime_eq",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					StartTimeStr: "12345",
				},
			},
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					StartTimeStr: "12345",
				},
			},
			true,
		},
		{
			"pod_hostip",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					HostIp: "10.0.0.1",
				},
			},
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					HostIp: "10.0.0.2",
				},
			},
			false,
		},
		{
			"pod_hostip_eq",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					HostIp: "10.0.0.1",
				},
			},
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					HostIp: "10.0.0.1",
				},
			},
			true,
		},
		{
			"containers",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{},
				},
			},
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						{
							Id: "foo",
						},
					},
				},
			},
			false,
		},
		{
			"containers_eq",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						{
							Id: "foo",
						},
					},
				},
			},
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						{
							Id: "foo",
						},
					},
				},
			},
			true,
		},
		{
			"containers_nil",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						nil,
					},
				},
			},
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						nil,
					},
				},
			},
			true,
		},
		{
			"containers_eq_not_nil",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						nil,
					},
				},
			},
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						{
							Id: "foo",
						},
					},
				},
			},
			false,
		},
		{
			"containers_count",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						{
							Id: "foo",
						},
						{
							Id: "foo",
						},
					},
				},
			},
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						{
							Id: "foo",
						},
					},
				},
			},
			false,
		},
		{
			"containers_count_eq",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						{
							Id: "foo",
						},
						{
							Id: "foo",
						},
					},
				},
			},
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						{
							Id: "foo",
						},
						{
							Id: "foo",
						},
					},
				},
			},
			true,
		},
		{
			"containers_name",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						{
							Name: "foo",
						},
					},
				},
			},
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						{
							Name: "bar",
						},
					},
				},
			},
			false,
		},
		{
			"containers_name_eq",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						{
							Name: "foo",
						},
					},
				},
			},
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						{
							Name: "foo",
						},
					},
				},
			},
			true,
		},
		{
			"containers_env",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						{
							Env: map[string]string{
								"foo": "not bar",
							},
						},
					},
				},
			},
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						{
							Env: map[string]string{
								"foo": "bar",
							},
						},
					},
				},
			},
			false,
		},
		{
			"containers_env_eq",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						{
							Env: map[string]string{
								"foo": "bar",
							},
						},
					},
				},
			},
			informer.ObjectMeta{
				Pod: &informer.PodInfo{
					Containers: []*informer.ContainerInfo{
						{
							Env: map[string]string{
								"foo": "bar",
							},
						},
					},
				},
			},
			true,
		},
		{
			"volume_claims",
			informer.ObjectMeta{
				Pod: &informer.PodInfo{VolumeClaims: []*informer.VolumeClaim{{VolumeName: "data", ClaimName: "pvc-a"}}},
			},
			informer.ObjectMeta{
				Pod: &informer.PodInfo{VolumeClaims: []*informer.VolumeClaim{{VolumeName: "data", ClaimName: "pvc-b"}}},
			},
			false,
		},
		{
			"persistent_volume_claim_eq",
			informer.ObjectMeta{
				PersistentVolume: &informer.PersistentVolumeInfo{ClaimNamespace: "default", ClaimName: "pvc-a"},
			},
			informer.ObjectMeta{
				PersistentVolume: &informer.PersistentVolumeInfo{ClaimNamespace: "default", ClaimName: "pvc-a"},
			},
			true,
		},
		{
			"persistent_volume_bound",
			informer.ObjectMeta{
				PersistentVolume: &informer.PersistentVolumeInfo{},
			},
			informer.ObjectMeta{
				PersistentVolume: &informer.PersistentVolumeInfo{ClaimNamespace: "default", ClaimName: "pvc-a"},
			},
			false,
		},
	}

	for i := range data {
		d := &data[i]

		t.Run(d.name, func(t *testing.T) {
			testUnchangedImpl(t, &d.o1, &d.o2, d.expectedResult)
		})
	}
}

func TestIPInfoEventHandlerRefreshesUpdatedEventTimestamp(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	inf := &Informers{
		log:          log,
		BaseNotifier: NewBaseNotifier(log),
	}
	observer := &eventObserver{id: "observer"}
	inf.BaseNotifier.Subscribe(observer)

	handler := inf.ipInfoEventHandler(context.Background())
	staleTimestamp := time.Now().Add(-time.Hour).Unix()
	start := time.Now().Unix()

	handler.UpdateFunc(
		&indexableEntity{EncodedMeta: &informer.ObjectMeta{
			Name:            "pod",
			Kind:            typePod,
			StatusTimeEpoch: staleTimestamp,
			Labels:          map[string]string{"version": "old"},
		}},
		&indexableEntity{EncodedMeta: &informer.ObjectMeta{
			Name:            "pod",
			Kind:            typePod,
			StatusTimeEpoch: staleTimestamp,
			Labels:          map[string]string{"version": "new"},
		}},
	)

	require.Len(t, observer.events, 1)
	assert.Equal(t, informer.EventType_UPDATED, observer.events[0].Type)
	assert.GreaterOrEqual(t, observer.events[0].Resource.StatusTimeEpoch, start)
}

func TestIPInfoEventHandlerRefreshesDeletedEventTimestamp(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	inf := &Informers{
		log:          log,
		BaseNotifier: NewBaseNotifier(log),
	}
	observer := &eventObserver{id: "observer"}
	inf.BaseNotifier.Subscribe(observer)

	handler := inf.ipInfoEventHandler(context.Background())
	staleTimestamp := time.Now().Add(-time.Hour).Unix()
	start := time.Now().Unix()

	handler.DeleteFunc(&indexableEntity{EncodedMeta: &informer.ObjectMeta{
		Name:            "pod",
		Kind:            typePod,
		StatusTimeEpoch: staleTimestamp,
	}})

	require.Len(t, observer.events, 1)
	assert.Equal(t, informer.EventType_DELETED, observer.events[0].Type)
	assert.GreaterOrEqual(t, observer.events[0].Resource.StatusTimeEpoch, start)
}

func TestRefreshStatusTimeEpochPreservesCurrentTimestamp(t *testing.T) {
	em := &informer.ObjectMeta{StatusTimeEpoch: time.Now().Add(time.Hour).Unix()}

	refreshStatusTimeEpoch(em)

	assert.Greater(t, em.StatusTimeEpoch, time.Now().Unix())
}

func TestPodVolumeClaims(t *testing.T) {
	inf := &Informers{config: &informersConfig{}}
	entity, err := inf.podToIndexableEntity(&v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "db-0", Namespace: "default", UID: "1234"},
		Spec: v1.PodSpec{Volumes: []v1.Volume{
			{Name: "data", VolumeSource: v1.VolumeSource{
				PersistentVolumeClaim: &v1.PersistentVolumeClaimVolumeSource{ClaimName: "data-db-0"},
			}},
			{Name: "tmp", VolumeSource: v1.VolumeSource{EmptyDir: &v1.EmptyDirVolumeSource{}}},
		}},
	})
	require.NoError(t, err)
	claims := entity.(*indexableEntity).EncodedMeta.Pod.VolumeClaims
	require.Len(t, claims, 1, "only the volumes that mount a PersistentVolumeClaim")
	assert.Equal(t, "data", claims[0].VolumeName)
	assert.Equal(t, "data-db-0", claims[0].ClaimName)
}

func TestPersistentVolumeToIndexableEntity(t *testing.T) {
	entity, err := persistentVolumeToIndexableEntity(&v1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pvc-5d1c"},
		Spec: v1.PersistentVolumeSpec{
			ClaimRef: &v1.ObjectReference{Namespace: "default", Name: "data-db-0"},
			PersistentVolumeSource: v1.PersistentVolumeSource{
				HostPath: &v1.HostPathVolumeSource{Path: "/var/local-path-provisioner/pvc-5d1c"},
			},
		},
	})
	require.NoError(t, err)
	meta := entity.(*indexableEntity).EncodedMeta
	assert.Equal(t, "pvc-5d1c", meta.Name)
	assert.Equal(t, typePersistentVolume, meta.Kind)
	assert.Equal(t, &informer.PersistentVolumeInfo{
		ClaimNamespace: "default",
		ClaimName:      "data-db-0",
		LocalPath:      "/var/local-path-provisioner/pvc-5d1c",
	}, meta.PersistentVolume)

	entity, err = persistentVolumeToIndexableEntity(&v1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pvc-unbound"},
		Spec: v1.PersistentVolumeSpec{PersistentVolumeSource: v1.PersistentVolumeSource{
			CSI: &v1.CSIPersistentVolumeSource{Driver: "ebs.csi.aws.com", VolumeHandle: "vol-1"},
		}},
	})
	require.NoError(t, err)
	assert.Empty(t, entity.(*indexableEntity).EncodedMeta.PersistentVolume.ClaimName)
	assert.Empty(t, entity.(*indexableEntity).EncodedMeta.PersistentVolume.LocalPath,
		"CSI volumes are found by their mount")
}
