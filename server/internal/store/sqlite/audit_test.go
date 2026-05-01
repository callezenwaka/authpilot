package sqlite

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"furnace/server/internal/domain"
	"furnace/server/internal/store"
)

func newAuditStore(t *testing.T) *SQLiteAuditStore {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "furnace.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s.Audit()
}

func auditEvent(id, eventType string) domain.AuditEvent {
	return domain.AuditEvent{
		ID:         id,
		Timestamp:  time.Now().UTC(),
		EventType:  eventType,
		Actor:      "system",
		ResourceID: "res_1",
	}
}

// --- Append + List ---

func TestAuditLog_AppendAndList(t *testing.T) {
	as := newAuditStore(t)

	as.Append(auditEvent("a1", "user.created"))
	as.Append(auditEvent("a2", "flow.complete"))
	as.Append(auditEvent("a3", "user.deleted"))

	events := as.List(store.AuditFilter{})
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}
	if events[0].ID != "a1" || events[2].ID != "a3" {
		t.Error("events not in insertion order")
	}
}

func TestAuditLog_FilterByEventType(t *testing.T) {
	as := newAuditStore(t)

	as.Append(auditEvent("b1", "user.created"))
	as.Append(auditEvent("b2", "flow.complete"))
	as.Append(auditEvent("b3", "user.created"))

	events := as.List(store.AuditFilter{EventType: "user.created"})
	if len(events) != 2 {
		t.Fatalf("expected 2 filtered events, got %d", len(events))
	}
	for _, e := range events {
		if e.EventType != "user.created" {
			t.Errorf("unexpected event type %q", e.EventType)
		}
	}
}

func TestAuditLog_FilterBySince(t *testing.T) {
	as := newAuditStore(t)

	old := domain.AuditEvent{
		ID:        "c1",
		Timestamp: time.Now().UTC().AddDate(0, 0, -5),
		EventType: "user.created",
		Actor:     "system",
	}
	recent := domain.AuditEvent{
		ID:        "c2",
		Timestamp: time.Now().UTC(),
		EventType: "user.created",
		Actor:     "system",
	}
	as.Append(old)
	as.Append(recent)

	cutoff := time.Now().UTC().AddDate(0, 0, -1)
	events := as.List(store.AuditFilter{Since: cutoff})
	if len(events) != 1 {
		t.Fatalf("expected 1 event after cutoff, got %d", len(events))
	}
	if events[0].ID != "c2" {
		t.Errorf("wrong event returned: %q", events[0].ID)
	}
}

// --- Hash chain integrity ---

func TestAuditLog_VerifyIntactChain(t *testing.T) {
	as := newAuditStore(t)

	for i := range 5 {
		_ = i
		as.Append(auditEvent("v"+string(rune('0'+i)), "user.created"))
	}

	result, err := as.Verify()
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !result.OK {
		t.Errorf("expected ok=true, got broken_at=%q message=%q", result.BrokenAt, result.Message)
	}
	if result.Checked != 5 {
		t.Errorf("expected 5 checked, got %d", result.Checked)
	}
}

func TestAuditLog_VerifyEmptyIsOK(t *testing.T) {
	as := newAuditStore(t)

	result, err := as.Verify()
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !result.OK {
		t.Errorf("empty log should verify ok")
	}
	if result.Checked != 0 {
		t.Errorf("expected 0 checked, got %d", result.Checked)
	}
}

func TestAuditLog_VerifyDetectsTamperedChainHash(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "furnace.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	as := s.Audit()

	as.Append(auditEvent("d1", "user.created"))
	as.Append(auditEvent("d2", "flow.complete"))
	as.Append(auditEvent("d3", "session.issued"))

	// Corrupt the chain_hash of the second row directly at the DB level.
	if _, err := s.db.Exec(`UPDATE audit_log SET chain_hash = 'deadbeef' WHERE id = 'd2'`); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	result, err := as.Verify()
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.OK {
		t.Fatal("expected ok=false after tampering chain_hash")
	}
	if result.BrokenAt != "d2" {
		t.Errorf("expected BrokenAt=d2, got %q", result.BrokenAt)
	}
	if !strings.Contains(result.Message, "d2") {
		t.Errorf("message should mention the offending ID: %q", result.Message)
	}
}

func TestAuditLog_VerifyDetectsTamperedEventData(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "furnace.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	as := s.Audit()

	as.Append(auditEvent("e1", "user.created"))
	as.Append(auditEvent("e2", "flow.complete"))

	// Corrupt the event_json of e2 directly (actor field altered).
	if _, err := s.db.Exec(`UPDATE audit_log SET event_json = '{"id":"e2","actor":"attacker"}' WHERE id = 'e2'`); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	result, err := as.Verify()
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.OK {
		t.Fatal("expected ok=false after tampering event_json")
	}
	if result.BrokenAt != "e2" {
		t.Errorf("expected BrokenAt=e2, got %q", result.BrokenAt)
	}
}

// --- Persistence across restarts ---

func TestAuditLog_ChainPersistsAcrossRestarts(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "furnace.db")

	s1, err := New(dbPath)
	if err != nil {
		t.Fatalf("New (first): %v", err)
	}
	as1 := s1.Audit()
	as1.Append(auditEvent("r1", "user.created"))
	as1.Append(auditEvent("r2", "flow.complete"))
	_ = s1.Close()

	s2, err := New(dbPath)
	if err != nil {
		t.Fatalf("New (second): %v", err)
	}
	defer func() { _ = s2.Close() }()
	as2 := s2.Audit()

	// Append one more after restart.
	as2.Append(auditEvent("r3", "session.issued"))

	result, err := as2.Verify()
	if err != nil {
		t.Fatalf("Verify after restart: %v", err)
	}
	if !result.OK {
		t.Errorf("chain broken after restart: broken_at=%q", result.BrokenAt)
	}
	if result.Checked != 3 {
		t.Errorf("expected 3 checked after restart, got %d", result.Checked)
	}
}
