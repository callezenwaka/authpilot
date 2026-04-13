package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"authpilot/server/internal/domain"
	"authpilot/server/internal/store"
	"authpilot/server/internal/store/memory"
)

func newAuditRouter() (http.Handler, *memory.AuditStore) {
	as := memory.NewAuditStore(0)
	router := NewRouter(Dependencies{
		Users:    memory.NewUserStore(),
		Groups:   memory.NewGroupStore(),
		Flows:    memory.NewFlowStore(),
		Sessions: memory.NewSessionStore(),
		Audit:    as,
	})
	return router, as
}

// ---------------------------------------------------------------------------
// Emission tests
// ---------------------------------------------------------------------------

func TestB2_UserCreated_EmitsAuditEvent(t *testing.T) {
	router, as := newAuditRouter()

	body := `{"id":"usr_audit1","email":"a@example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	httptest.NewRecorder()
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("create user: want 201, got %d", rec.Code)
	}
	events := as.List(store.AuditFilter{EventType: "user.created"})
	if len(events) != 1 {
		t.Fatalf("expected 1 user.created event, got %d", len(events))
	}
	if events[0].ResourceID != "usr_audit1" {
		t.Errorf("resource_id: want usr_audit1, got %q", events[0].ResourceID)
	}
}

func TestB2_UserUpdated_EmitsAuditEvent(t *testing.T) {
	router, as := newAuditRouter()

	// Create first.
	cr := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(`{"id":"usr_upd","email":"upd@example.com"}`))
	cr.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(httptest.NewRecorder(), cr)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/users/usr_upd", strings.NewReader(`{"email":"upd2@example.com"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("update user: want 200, got %d", rec.Code)
	}
	events := as.List(store.AuditFilter{EventType: "user.updated"})
	if len(events) != 1 {
		t.Fatalf("expected 1 user.updated event, got %d", len(events))
	}
}

func TestB2_UserDeleted_EmitsAuditEvent(t *testing.T) {
	router, as := newAuditRouter()

	cr := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(`{"id":"usr_del","email":"del@example.com"}`))
	cr.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(httptest.NewRecorder(), cr)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/usr_del", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete user: want 204, got %d", rec.Code)
	}
	events := as.List(store.AuditFilter{EventType: "user.deleted"})
	if len(events) != 1 {
		t.Fatalf("expected 1 user.deleted event, got %d", len(events))
	}
	if events[0].ResourceID != "usr_del" {
		t.Errorf("resource_id: want usr_del, got %q", events[0].ResourceID)
	}
}

func TestB2_FlowComplete_EmitsAuditEvent(t *testing.T) {
	users := memory.NewUserStore()
	as := memory.NewAuditStore(0)
	if _, err := users.Create(domain.User{ID: "usr_fc", Email: "fc@example.com", Active: true}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	router := NewRouter(Dependencies{
		Users:    users,
		Groups:   memory.NewGroupStore(),
		Flows:    memory.NewFlowStore(),
		Sessions: memory.NewSessionStore(),
		Audit:    as,
	})

	// Create flow.
	fr := httptest.NewRequest(http.MethodPost, "/api/v1/flows", nil)
	frec := httptest.NewRecorder()
	router.ServeHTTP(frec, fr)
	var flow map[string]any
	decodeJSON(t, frec, &flow)
	flowID := flow["id"].(string)

	// Select user (no MFA → goes to complete).
	req := httptest.NewRequest(http.MethodPost, "/api/v1/flows/"+flowID+"/select-user",
		strings.NewReader(`{"user_id":"usr_fc"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("select-user: want 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	events := as.List(store.AuditFilter{EventType: "flow.complete"})
	if len(events) != 1 {
		t.Fatalf("expected 1 flow.complete event, got %d", len(events))
	}
	if events[0].ResourceID != flowID {
		t.Errorf("resource_id: want %q, got %q", flowID, events[0].ResourceID)
	}
}

func TestB2_FlowDenied_EmitsAuditEvent(t *testing.T) {
	users := memory.NewUserStore()
	as := memory.NewAuditStore(0)
	if _, err := users.Create(domain.User{ID: "usr_push", Email: "push@example.com", MFAMethod: "push", Active: true}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	router := NewRouter(Dependencies{
		Users:    users,
		Groups:   memory.NewGroupStore(),
		Flows:    memory.NewFlowStore(),
		Sessions: memory.NewSessionStore(),
		Audit:    as,
	})

	fr := httptest.NewRequest(http.MethodPost, "/api/v1/flows", nil)
	frec := httptest.NewRecorder()
	router.ServeHTTP(frec, fr)
	var flow map[string]any
	decodeJSON(t, frec, &flow)
	flowID := flow["id"].(string)

	su := httptest.NewRequest(http.MethodPost, "/api/v1/flows/"+flowID+"/select-user",
		strings.NewReader(`{"user_id":"usr_push"}`))
	su.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(httptest.NewRecorder(), su)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/flows/"+flowID+"/deny", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("deny: want 200, got %d", rec.Code)
	}
	events := as.List(store.AuditFilter{EventType: "flow.denied"})
	if len(events) != 1 {
		t.Fatalf("expected 1 flow.denied event, got %d", len(events))
	}
}

// ---------------------------------------------------------------------------
// GET /api/v1/audit
// ---------------------------------------------------------------------------

func TestB2_AuditList_Empty(t *testing.T) {
	router, _ := newAuditRouter()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var events []domain.AuditEvent
	decodeJSON(t, rec, &events)
	if len(events) != 0 {
		t.Errorf("expected empty list, got %d events", len(events))
	}
}

func TestB2_AuditList_EventTypeFilter(t *testing.T) {
	router, _ := newAuditRouter()

	// Create two users — generates two user.created events.
	for _, id := range []string{"usr_f1", "usr_f2"} {
		body := `{"id":"` + id + `","email":"` + id + `@example.com"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(httptest.NewRecorder(), req)
	}
	// Delete one — generates user.deleted.
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/usr_f1", nil)
	router.ServeHTTP(httptest.NewRecorder(), req)

	// Filter by user.created — should return exactly 2.
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/audit?event_type=user.created", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req2)

	var events []domain.AuditEvent
	decodeJSON(t, rec, &events)
	if len(events) != 2 {
		t.Errorf("expected 2 user.created events, got %d", len(events))
	}
}

func TestB2_AuditList_SinceFilter(t *testing.T) {
	router, as := newAuditRouter()

	// Manually inject an old event.
	as.Append(domain.AuditEvent{
		ID:        "aud_old",
		Timestamp: time.Now().Add(-2 * time.Hour).UTC(),
		EventType: "user.created",
		Actor:     "system",
	})

	// Create a user now — recent event.
	body := `{"id":"usr_since","email":"since@example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(httptest.NewRecorder(), req)

	since := time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339)
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/audit?since="+since, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req2)

	var events []domain.AuditEvent
	decodeJSON(t, rec, &events)
	if len(events) != 1 {
		t.Errorf("expected 1 recent event, got %d", len(events))
	}
	if events[0].ResourceID != "usr_since" {
		t.Errorf("expected usr_since event, got %q", events[0].ResourceID)
	}
}

func TestB2_AuditList_InvalidSince_Returns400(t *testing.T) {
	router, _ := newAuditRouter()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit?since=notadate", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", rec.Code)
	}
}

func TestB2_AuditList_NilStore_ReturnsEmpty(t *testing.T) {
	router := NewRouter(Dependencies{
		Users:    memory.NewUserStore(),
		Groups:   memory.NewGroupStore(),
		Flows:    memory.NewFlowStore(),
		Sessions: memory.NewSessionStore(),
		Audit:    nil,
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("want 200, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// GET /api/v1/audit/export
// ---------------------------------------------------------------------------

func TestB2_AuditExport_JSONND(t *testing.T) {
	router, as := newAuditRouter()
	as.Append(domain.AuditEvent{
		ID: "aud_1", Timestamp: time.Now().UTC(),
		EventType: "user.created", Actor: "system", ResourceID: "usr_x",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/export?format=json-nd", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/x-ndjson" {
		t.Errorf("Content-Type: want application/x-ndjson, got %q", ct)
	}
	// Each line is a JSON object.
	line := strings.TrimSpace(rec.Body.String())
	var event domain.AuditEvent
	if err := json.Unmarshal([]byte(line), &event); err != nil {
		t.Errorf("json-nd line not valid JSON: %v", err)
	}
}

func TestB2_AuditExport_CEF(t *testing.T) {
	router, as := newAuditRouter()
	as.Append(domain.AuditEvent{
		ID: "aud_2", Timestamp: time.Now().UTC(),
		EventType: "flow.complete", Actor: "usr_y", ResourceID: "flow_z",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/export?format=cef", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.HasPrefix(body, "CEF:0|") {
		t.Errorf("expected CEF prefix, got: %q", body[:min(40, len(body))])
	}
	if !strings.Contains(body, "flow.complete") {
		t.Error("expected event type in CEF output")
	}
}

func TestB2_AuditExport_Syslog(t *testing.T) {
	router, as := newAuditRouter()
	as.Append(domain.AuditEvent{
		ID: "aud_3", Timestamp: time.Now().UTC(),
		EventType: "user.deleted", Actor: "system", ResourceID: "usr_gone",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/export?format=syslog", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "<110>1 ") {
		t.Errorf("expected RFC5424 PRI+version, got: %q", body[:min(40, len(body))])
	}
	if !strings.Contains(body, "user.deleted") {
		t.Error("expected event type in syslog output")
	}
}

func TestB2_AuditExport_MissingFormat_Returns400(t *testing.T) {
	router, _ := newAuditRouter()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/export", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", rec.Code)
	}
}

func TestB2_AuditExport_UnknownFormat_Returns400(t *testing.T) {
	router, _ := newAuditRouter()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/export?format=xml", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", rec.Code)
	}
}

func TestB2_AuditExport_NilStore_Returns501(t *testing.T) {
	router := NewRouter(Dependencies{
		Users:    memory.NewUserStore(),
		Groups:   memory.NewGroupStore(),
		Flows:    memory.NewFlowStore(),
		Sessions: memory.NewSessionStore(),
		Audit:    nil,
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/export?format=json-nd", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("want 501, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Ring-buffer eviction
// ---------------------------------------------------------------------------

func TestB2_RingBuffer_Eviction(t *testing.T) {
	as := memory.NewAuditStore(3)
	for i := range 5 {
		as.Append(domain.AuditEvent{
			ID:        fmt.Sprintf("aud_%d", i),
			EventType: "test",
			Actor:     "system",
		})
	}
	events := as.List(store.AuditFilter{})
	if len(events) != 3 {
		t.Errorf("ring buffer cap=3: expected 3 events, got %d", len(events))
	}
}
