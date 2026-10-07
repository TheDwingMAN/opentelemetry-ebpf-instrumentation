// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package statagg

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	ikube "go.opentelemetry.io/obi/pkg/internal/kube"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
)

const (
	memPodUID = "0f6b2d4e-8c1a-4b7e-9d3f-2a5c7e9b1d4f"
	memCtrID  = "5e8a1c3f7b9d2e4a6c8f0b1d3e5a7c9f1b3d5e7a9c1f3b5d7e9a1c3f5b7d9e1a"
)

// mutableStore is a PodStore whose pod can be deleted, as the Kubernetes
// store deletes a pod once it completes.
type mutableStore struct {
	pod   *ikube.CachedObjMeta
	calls int
}

func (s *mutableStore) PodByUID(uid string) *ikube.CachedObjMeta {
	s.calls++
	if s.pod != nil && uid == memPodUID {
		return s.pod
	}
	return nil
}

func (s *mutableStore) PodContainerByContainerID(id string) (*ikube.CachedObjMeta, string) {
	s.calls++
	if s.pod != nil && id == memCtrID {
		return s.pod, "worker"
	}
	return nil, ""
}

// A completed pod the store deleted keeps the name the store last gave it,
// for the TTL after that answer.
func TestPodMemory_RemembersADeletedPodForTheTTL(t *testing.T) {
	pod := &ikube.CachedObjMeta{Meta: &informer.ObjectMeta{Name: "verify-paths", Namespace: "lab"}}
	store := &mutableStore{pod: pod}
	clock := newFakeClock()
	m := NewPodMemory(store, 0, clock.Now)

	assert.Same(t, pod, m.PodByUID(memPodUID))
	meta, name := m.PodContainerByContainerID(memCtrID)
	assert.Same(t, pod, meta)
	assert.Equal(t, "worker", name)

	store.pod = nil
	clock.Advance(DefaultCgroupTombstoneTTL - time.Second)
	assert.Same(t, pod, m.PodByUID(memPodUID), "deleted from the store: remembered")
	meta, name = m.PodContainerByContainerID(memCtrID)
	assert.Same(t, pod, meta)
	assert.Equal(t, "worker", name)

	clock.Advance(time.Second)
	assert.Nil(t, m.PodByUID(memPodUID), "the TTL after the store's last answer: forgotten")
	meta, _ = m.PodContainerByContainerID(memCtrID)
	assert.Nil(t, meta)
}

// Only what the store answered is remembered, and the store's answer comes
// first.
func TestPodMemory_AnswersFromTheStoreFirst(t *testing.T) {
	store := &mutableStore{}
	clock := newFakeClock()
	m := NewPodMemory(store, time.Minute, clock.Now)
	assert.Nil(t, m.PodByUID(memPodUID), "never known")

	old := &ikube.CachedObjMeta{Meta: &informer.ObjectMeta{Name: "job-v1"}}
	store.pod = old
	assert.Same(t, old, m.PodByUID(memPodUID))
	updated := &ikube.CachedObjMeta{Meta: &informer.ObjectMeta{Name: "job-v1", Labels: map[string]string{"v": "2"}}}
	store.pod = updated
	assert.Same(t, updated, m.PodByUID(memPodUID))
	store.pod = nil
	assert.Same(t, updated, m.PodByUID(memPodUID), "the last answer is remembered")

	// The containers of a pod with no container IDs yet are under "" in
	// the store: never remembered.
	store.calls = 0
	meta, _ := m.PodContainerByContainerID("")
	assert.Nil(t, meta)
	assert.Equal(t, 1, store.calls)
}

// Expired pods are swept, so the memory stays bounded by what the store
// answered within the TTL.
func TestPodMemory_SweepsExpiredPods(t *testing.T) {
	pod := &ikube.CachedObjMeta{Meta: &informer.ObjectMeta{Name: "job"}}
	store := &mutableStore{pod: pod}
	clock := newFakeClock()
	m := NewPodMemory(store, time.Minute, clock.Now)
	m.PodByUID(memPodUID)
	m.PodContainerByContainerID(memCtrID)
	store.pod = nil

	clock.Advance(time.Minute + podSweepInterval)
	m.PodByUID("another")
	m.mu.Lock()
	defer m.mu.Unlock()
	assert.Empty(t, m.pods)
	assert.Empty(t, m.containers)
}
