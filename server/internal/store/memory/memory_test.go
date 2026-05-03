package memory

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"furnace/server/internal/domain"
	"furnace/server/internal/store"
)

func TestUserCRUD(t *testing.T) {
	s := NewUserStore()
	now := time.Now().UTC()

	created, err := s.Create(domain.User{ID: "usr_1", Email: "a@example.com", CreatedAt: now})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if created.ID != "usr_1" {
		t.Fatalf("unexpected user id: %s", created.ID)
	}

	got, err := s.GetByID("usr_1")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if got.Email != "a@example.com" {
		t.Fatalf("unexpected email: %s", got.Email)
	}

	got.Email = "updated@example.com"
	if _, err := s.Update(got); err != nil {
		t.Fatalf("update user: %v", err)
	}

	list, err := s.List()
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("unexpected user count: %d", len(list))
	}

	if err := s.Delete("usr_1"); err != nil {
		t.Fatalf("delete user: %v", err)
	}
}

func TestFlowCleanup(t *testing.T) {
	s := NewFlowStore()
	now := time.Now().UTC()

	_, _ = s.Create(domain.Flow{ID: "flow_old", ExpiresAt: now.Add(-time.Minute)})
	_, _ = s.Create(domain.Flow{ID: "flow_new", ExpiresAt: now.Add(time.Minute)})

	removed, err := s.DeleteExpired(now)
	if err != nil {
		t.Fatalf("cleanup flows: %v", err)
	}
	if removed != 1 {
		t.Fatalf("expected 1 removed flow, got %d", removed)
	}
}

// TestConsumeAuthCode_ConcurrentRedeem verifies the atomic CAS guarantee:
// when N goroutines race to redeem the same auth code, exactly one wins.
// Regression test for the lookup-then-update race that allowed code replay.
func TestConsumeAuthCode_ConcurrentRedeem(t *testing.T) {
	s := NewFlowStore()
	now := time.Now().UTC()
	if _, err := s.Create(domain.Flow{
		ID:        "flow_race",
		AuthCode:  "code-xyz",
		CreatedAt: now,
		ExpiresAt: now.Add(5 * time.Minute),
	}); err != nil {
		t.Fatalf("create flow: %v", err)
	}

	const goroutines = 64
	var wg sync.WaitGroup
	var successes, failures atomic.Int64
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			f, err := s.ConsumeAuthCode("code-xyz")
			if err == nil && f.ID == "flow_race" {
				successes.Add(1)
				return
			}
			if err == store.ErrNotFound {
				failures.Add(1)
				return
			}
			t.Errorf("unexpected error: %v", err)
		}()
	}
	wg.Wait()

	if got := successes.Load(); got != 1 {
		t.Errorf("expected exactly 1 success, got %d", got)
	}
	if got := failures.Load(); got != goroutines-1 {
		t.Errorf("expected %d failures, got %d", goroutines-1, got)
	}

	// Code is now consumed; a fresh attempt also fails.
	if _, err := s.ConsumeAuthCode("code-xyz"); err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound after consumption, got %v", err)
	}
}

func TestUserStore_DuplicateEmail(t *testing.T) {
	s := NewUserStore()
	u := domain.User{ID: "usr_a", Email: "alice@example.com"}
	if _, err := s.Create(u); err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err := s.Create(domain.User{ID: "usr_b", Email: "alice@example.com"})
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected ErrConflict on duplicate email, got %v", err)
	}
}
