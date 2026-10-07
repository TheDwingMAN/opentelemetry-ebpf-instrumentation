// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package statagg // import "go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"

import (
	"sync"
	"time"

	ikube "go.opentelemetry.io/obi/pkg/internal/kube"
)

// maxRememberedPods bounds the pods, and the containers, a PodMemory keeps:
// a node runs about a hundred pods at a time, and this covers a pod a second
// for the whole TTL several times over.
const maxRememberedPods = 8192

// podSweepInterval is how often a PodMemory forgets what has expired.
const podSweepInterval = time.Minute

// PodMemory is a PodStore that answers from a Kubernetes store and, for a pod
// the store no longer has, with what the store last answered for it, for a
// TTL after that answer. The store deletes a pod once it completes, while
// the kernel keeps counting for its cgroup (writeback of the files it
// wrote), and a key of an aggregation map may be decorated again, or first
// decorated from a cgroup the index remembered, after that: such a pod keeps
// its name, as the cgroup index keeps its identity as a tombstone. Only what
// the store has answered is remembered: a pod it never had stays unknown.
//
// It is safe for concurrent use: the families share one.
type PodMemory struct {
	store PodStore
	ttl   time.Duration
	clock func() time.Time

	mu         sync.Mutex
	pods       map[string]rememberedPod
	containers map[string]rememberedContainer
	lastSweep  time.Time
}

type rememberedPod struct {
	meta *ikube.CachedObjMeta
	// at is when the store last answered it.
	at time.Time
}

type rememberedContainer struct {
	rememberedPod
	name string
}

// NewPodMemory remembers what store answers for ttl
// (DefaultCgroupTombstoneTTL when 0); clock is time.Now when nil.
func NewPodMemory(store PodStore, ttl time.Duration, clock func() time.Time) *PodMemory {
	if ttl == 0 {
		ttl = DefaultCgroupTombstoneTTL
	}
	if clock == nil {
		clock = time.Now
	}
	return &PodMemory{
		store: store, ttl: ttl, clock: clock,
		pods: map[string]rememberedPod{}, containers: map[string]rememberedContainer{},
	}
}

// PodByUID returns the store's pod of uid, or the one it last returned for
// uid less than the TTL ago.
func (m *PodMemory) PodByUID(uid string) *ikube.CachedObjMeta {
	meta := m.store.PodByUID(uid)
	if uid == "" {
		return meta
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.clock()
	m.sweep(now)
	if meta != nil {
		if _, ok := m.pods[uid]; ok || len(m.pods) < maxRememberedPods {
			m.pods[uid] = rememberedPod{meta: meta, at: now}
		}
		return meta
	}
	if p, ok := m.pods[uid]; ok && now.Sub(p.at) < m.ttl {
		return p.meta
	}
	return nil
}

// PodContainerByContainerID returns the store's pod and container name of
// a container ID, or the ones it last returned for it less than the TTL ago.
func (m *PodMemory) PodContainerByContainerID(containerID string) (*ikube.CachedObjMeta, string) {
	meta, name := m.store.PodContainerByContainerID(containerID)
	// The store indexes the containers of a pod with no container IDs yet
	// under "": that answer is not the container's.
	if containerID == "" {
		return meta, name
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.clock()
	m.sweep(now)
	if meta != nil {
		if _, ok := m.containers[containerID]; ok || len(m.containers) < maxRememberedPods {
			m.containers[containerID] = rememberedContainer{rememberedPod: rememberedPod{meta: meta, at: now}, name: name}
		}
		return meta, name
	}
	if c, ok := m.containers[containerID]; ok && now.Sub(c.at) < m.ttl {
		return c.meta, c.name
	}
	return nil, ""
}

// sweep forgets, at most once per podSweepInterval, what expired.
func (m *PodMemory) sweep(now time.Time) {
	if now.Sub(m.lastSweep) < podSweepInterval {
		return
	}
	m.lastSweep = now
	for uid, p := range m.pods {
		if now.Sub(p.at) >= m.ttl {
			delete(m.pods, uid)
		}
	}
	for id, c := range m.containers {
		if now.Sub(c.at) >= m.ttl {
			delete(m.containers, id)
		}
	}
}
