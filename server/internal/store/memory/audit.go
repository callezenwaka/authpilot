package memory

import (
	"sync"

	"furnace/server/internal/domain"
	"furnace/server/internal/store"
)

const defaultAuditCap = 10_000

// AuditStore is a thread-safe in-memory ring buffer for audit events.
// When the buffer is full the oldest entry is overwritten.
type AuditStore struct {
	mu  sync.RWMutex
	buf []domain.AuditEvent
	cap int
	// head points to the next write slot; wraps at cap.
	head int
	// size tracks how many entries are populated (≤ cap).
	size int
}

// NewAuditStore returns an AuditStore with the given capacity.
// If cap ≤ 0 the default (10 000) is used.
func NewAuditStore(cap int) *AuditStore {
	if cap <= 0 {
		cap = defaultAuditCap
	}
	return &AuditStore{
		buf: make([]domain.AuditEvent, cap),
		cap: cap,
	}
}

func (s *AuditStore) Append(event domain.AuditEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf[s.head] = event
	s.head = (s.head + 1) % s.cap
	if s.size < s.cap {
		s.size++
	}
}

func (s *AuditStore) List(filter store.AuditFilter) []domain.AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]domain.AuditEvent, 0, s.size)
	// Iterate from oldest to newest.
	start := 0
	if s.size == s.cap {
		// Buffer is full — oldest entry is at head.
		start = s.head
	}
	for i := 0; i < s.size; i++ {
		e := s.buf[(start+i)%s.cap]
		if filter.EventType != "" && e.EventType != filter.EventType {
			continue
		}
		if !filter.Since.IsZero() && e.Timestamp.Before(filter.Since) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// Verify always returns ok=true for the in-memory store. The ring buffer has
// no tamper-evident chain; use SQLiteAuditStore for integrity guarantees.
func (s *AuditStore) Verify() (store.AuditVerifyResult, error) {
	s.mu.RLock()
	n := s.size
	s.mu.RUnlock()
	return store.AuditVerifyResult{
		OK:      true,
		Checked: n,
		Message: "in-memory store: no tamper-evident chain",
	}, nil
}
