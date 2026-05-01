package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"furnace/server/internal/authevents"
	"furnace/server/internal/domain"
	flowengine "furnace/server/internal/flow"
	"furnace/server/internal/store/memory"
)

// captureSink records emitted events for assertion in tests.
type captureSink struct {
	mu     sync.Mutex
	events []authevents.Event
}

func (s *captureSink) Emit(e authevents.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
}

func (s *captureSink) all() []authevents.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]authevents.Event, len(s.events))
	copy(out, s.events)
	return out
}

func (s *captureSink) firstOfType(typ string) (authevents.Event, bool) {
	for _, e := range s.all() {
		if e.Type == typ {
			return e, true
		}
	}
	return authevents.Event{}, false
}

func newAuthEventsTestRouter(sink *captureSink) (http.Handler, *memory.FlowStore, *memory.UserStore) {
	users := memory.NewUserStore()
	flows := memory.NewFlowStore()
	groups := memory.NewGroupStore()
	sessions := memory.NewSessionStore()
	router := NewRouter(Dependencies{
		Users:         users,
		Groups:        groups,
		Flows:         flows,
		Sessions:      sessions,
		APIKey:        "test-api-key",
		AuthEventSink: sink,
	})
	return router, flows, users
}

// TestAuthEvent_KeyRejected verifies that a missing/wrong API key emits TypeKeyRejected.
func TestAuthEvent_KeyRejected(t *testing.T) {
	sink := &captureSink{}
	router, _, _ := newAuthEventsTestRouter(sink)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	req.Header.Set("Authorization", "Bearer wrong-key")
	router.ServeHTTP(httptest.NewRecorder(), req)

	e, ok := sink.firstOfType(authevents.TypeKeyRejected)
	if !ok {
		t.Fatal("expected key_rejected event, got none")
	}
	if e.Time.IsZero() {
		t.Error("event time must not be zero")
	}
}

// TestAuthEvent_SignupAbuse verifies that hitting the rate limit emits TypeSignupAbuse.
func TestAuthEvent_SignupAbuse(t *testing.T) {
	sink := &captureSink{}
	users := memory.NewUserStore()
	flows := memory.NewFlowStore()
	sessions := memory.NewSessionStore()
	rl := NewRateLimiter(2, time.Minute)
	router := NewRouter(Dependencies{
		Users:         users,
		Groups:        memory.NewGroupStore(),
		Flows:         flows,
		Sessions:      sessions,
		APIKey:        "test-api-key",
		RateLimit:     2,
		AuthEventSink: sink,
	})
	// Exhaust the limiter by wiring it directly via the router's internal path.
	// The router creates its own limiter from dep.RateLimit, so we drive it via
	// repeated requests with the correct API key.
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
		req.Header.Set("Authorization", "Bearer test-api-key")
		router.ServeHTTP(httptest.NewRecorder(), req)
	}
	_ = rl // suppresses unused warning

	_, ok := sink.firstOfType(authevents.TypeSignupAbuse)
	if !ok {
		t.Fatal("expected signup_abuse event after rate limit exhausted, got none")
	}
}

// TestAuthEvent_MFAMismatch verifies that a wrong MFA code emits TypeMFAMismatch.
func TestAuthEvent_MFAMismatch(t *testing.T) {
	sink := &captureSink{}
	router, flows, users := newAuthEventsTestRouter(sink)

	// Seed a user with mfa_fail scenario so the code check always fails.
	u := domain.User{ID: "usr_mfa", Email: "mfa@example.com", MFAMethod: "totp", Active: true}
	if _, err := users.Create(u); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	flow := domain.Flow{
		ID:        "flow_mfa",
		State:     string(flowengine.StateMFAPending),
		UserID:    u.ID,
		Scenario:  string(flowengine.ScenarioMFAFail),
		CreatedAt: now,
		ExpiresAt: now.Add(30 * time.Minute),
	}
	if _, err := flows.Create(flow); err != nil {
		t.Fatal(err)
	}

	body := `{"code":"wrong-code"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/flows/flow_mfa/verify-mfa",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-api-key")
	router.ServeHTTP(httptest.NewRecorder(), req)

	e, ok := sink.firstOfType(authevents.TypeMFAMismatch)
	if !ok {
		t.Fatal("expected mfa_mismatch event, got none")
	}
	if e.FlowID != "flow_mfa" {
		t.Errorf("FlowID: want flow_mfa, got %q", e.FlowID)
	}
}

// TestAuthEvent_LoginFailed verifies that a conclusively denied flow emits TypeLoginFailed.
// StateMFADenied is reached via the /deny endpoint (admin or push-deny flow).
func TestAuthEvent_LoginFailed(t *testing.T) {
	sink := &captureSink{}
	router, flows, users := newAuthEventsTestRouter(sink)

	u := domain.User{ID: "usr_deny", Email: "deny@example.com", MFAMethod: "push", Active: true}
	if _, err := users.Create(u); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	flow := domain.Flow{
		ID:        "flow_deny",
		State:     string(flowengine.StateMFAPending),
		UserID:    u.ID,
		Scenario:  string(flowengine.ScenarioNormal),
		CreatedAt: now,
		ExpiresAt: now.Add(30 * time.Minute),
	}
	if _, err := flows.Create(flow); err != nil {
		t.Fatal(err)
	}

	// POST /deny transitions flow → StateMFADenied, which fires login_failed.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/flows/flow_deny/deny",
		strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-api-key")
	router.ServeHTTP(httptest.NewRecorder(), req)

	e, ok := sink.firstOfType(authevents.TypeLoginFailed)
	if !ok {
		t.Fatal("expected login_failed event, got none")
	}
	if e.UserID != u.ID {
		t.Errorf("UserID: want %q, got %q", u.ID, e.UserID)
	}
	if e.FlowID != "flow_deny" {
		t.Errorf("FlowID: want flow_deny, got %q", e.FlowID)
	}
}
