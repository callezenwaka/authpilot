package memory

import (
	"sort"
	"sync"
	"time"

	"furnace/server/internal/domain"
	"furnace/server/internal/store"
)

type FlowStore struct {
	mu    sync.RWMutex
	flows map[string]domain.Flow
}

func NewFlowStore() *FlowStore {
	return &FlowStore{flows: make(map[string]domain.Flow)}
}

func (s *FlowStore) Create(flow domain.Flow) (domain.Flow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flows[flow.ID] = flow
	return flow, nil
}

func (s *FlowStore) GetByID(id string) (domain.Flow, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	flow, ok := s.flows[id]
	if !ok {
		return domain.Flow{}, store.ErrNotFound
	}
	return flow, nil
}

func (s *FlowStore) List() ([]domain.Flow, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]domain.Flow, 0, len(s.flows))
	for _, flow := range s.flows {
		out = append(out, flow)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *FlowStore) Update(flow domain.Flow) (domain.Flow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.flows[flow.ID]; !ok {
		return domain.Flow{}, store.ErrNotFound
	}
	s.flows[flow.ID] = flow
	return flow, nil
}

func (s *FlowStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.flows[id]; !ok {
		return store.ErrNotFound
	}
	delete(s.flows, id)
	return nil
}

func (s *FlowStore) ConsumeAuthCode(code string) (domain.Flow, error) {
	if code == "" {
		return domain.Flow{}, store.ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, flow := range s.flows {
		if flow.AuthCode == code {
			consumed := flow
			flow.AuthCode = ""
			s.flows[id] = flow
			return consumed, nil
		}
	}
	return domain.Flow{}, store.ErrNotFound
}

func (s *FlowStore) DeleteExpired(now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for id, flow := range s.flows {
		if flow.ExpiresAt.Before(now) {
			delete(s.flows, id)
			removed++
		}
	}
	return removed, nil
}
