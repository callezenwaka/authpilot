package memory

import (
	"sort"
	"sync"

	"furnace/server/internal/domain"
	"furnace/server/internal/store"
)

type UserStore struct {
	mu    sync.RWMutex
	users map[string]domain.User
}

func NewUserStore() *UserStore {
	return &UserStore{users: make(map[string]domain.User)}
}

func (s *UserStore) Create(user domain.User) (domain.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.Email == user.Email {
			return domain.User{}, store.ErrConflict
		}
	}
	s.users[user.ID] = cloneUser(user)
	return cloneUser(user), nil
}

func (s *UserStore) GetByID(id string) (domain.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.users[id]
	if !ok {
		return domain.User{}, store.ErrNotFound
	}
	return cloneUser(user), nil
}

func (s *UserStore) List() ([]domain.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]domain.User, 0, len(s.users))
	for _, user := range s.users {
		out = append(out, cloneUser(user))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *UserStore) Update(user domain.User) (domain.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[user.ID]; !ok {
		return domain.User{}, store.ErrNotFound
	}
	s.users[user.ID] = cloneUser(user)
	return cloneUser(user), nil
}

func (s *UserStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[id]; !ok {
		return store.ErrNotFound
	}
	delete(s.users, id)
	return nil
}

func cloneUser(in domain.User) domain.User {
	out := in
	out.Groups = append([]string(nil), in.Groups...)
	if in.Claims != nil {
		out.Claims = make(map[string]any, len(in.Claims))
		for k, v := range in.Claims {
			out.Claims[k] = v
		}
	}
	return out
}
