package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"authpilot/server/internal/domain"
	flowengine "authpilot/server/internal/flow"
	"authpilot/server/internal/store/memory"
)

func newFlowRouterForTest() (http.Handler, *memory.UserStore, *memory.FlowStore) {
	users := memory.NewUserStore()
	groups := memory.NewGroupStore()
	flows := memory.NewFlowStore()
	sessions := memory.NewSessionStore()

	router := NewRouter(Dependencies{
		Users:    users,
		Groups:   groups,
		Flows:    flows,
		Sessions: sessions,
	})
	return router, users, flows
}

func seedUser(t *testing.T, users *memory.UserStore, id, mfaMethod, nextFlow string) {
	t.Helper()
	_, err := users.Create(domain.User{
		ID:          id,
		Email:       id + "@example.com",
		DisplayName: strings.ToUpper(id),
		MFAMethod:   mfaMethod,
		NextFlow:    nextFlow,
		CreatedAt:   time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
}

func seedFlow(t *testing.T, flows *memory.FlowStore, id string) {
	t.Helper()
	now := time.Now().UTC()
	_, err := flows.Create(domain.Flow{
		ID:        id,
		State:     string(flowengine.StateInitiated),
		Scenario:  string(flowengine.ScenarioNormal),
		Protocol:  "oidc",
		CreatedAt: now,
		ExpiresAt: now.Add(30 * time.Minute),
	})
	if err != nil {
		t.Fatalf("seed flow: %v", err)
	}
}

func doJSON(t *testing.T, router http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var payload io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal json: %v", err)
		}
		payload = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, payload)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

func doForm(t *testing.T, router http.Handler, method, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

func TestM2_NoMFAFlowCompletes(t *testing.T) {
	router, users, flows := newFlowRouterForTest()
	seedUser(t, users, "usr_nomfa", "none", "normal")
	seedFlow(t, flows, "flow_nomfa")

	rr := doJSON(t, router, http.MethodPost, "/api/v1/flows/flow_nomfa/select-user", map[string]string{
		"user_id": "usr_nomfa",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}

	got, err := flows.GetByID("flow_nomfa")
	if err != nil {
		t.Fatalf("load flow: %v", err)
	}
	if got.State != string(flowengine.StateComplete) {
		t.Fatalf("expected complete state, got %q", got.State)
	}
}

func TestM2_MFAFlowCompletesThroughLoginPages(t *testing.T) {
	router, users, flows := newFlowRouterForTest()
	seedUser(t, users, "usr_totp", "totp", "normal")
	seedFlow(t, flows, "flow_mfa")

	pick := doForm(t, router, http.MethodPost, "/login/select-user?flow_id=flow_mfa", url.Values{
		"user_id": {"usr_totp"},
	})
	if pick.Code != http.StatusFound {
		t.Fatalf("expected 302 from user select, got %d body=%s", pick.Code, pick.Body.String())
	}
	if got := pick.Header().Get("Location"); got != "/login/mfa?flow_id=flow_mfa" {
		t.Fatalf("unexpected select redirect: %q", got)
	}

	verify := doForm(t, router, http.MethodPost, "/login/mfa?flow_id=flow_mfa", url.Values{
		"code": {"123456"},
	})
	if verify.Code != http.StatusFound {
		t.Fatalf("expected 302 from mfa submit, got %d body=%s", verify.Code, verify.Body.String())
	}

	advanceReq := httptest.NewRequest(http.MethodGet, "/login/mfa?flow_id=flow_mfa", nil)
	advanceRR := httptest.NewRecorder()
	router.ServeHTTP(advanceRR, advanceReq)
	if advanceRR.Code != http.StatusFound {
		t.Fatalf("expected 302 from mfa page auto-advance, got %d body=%s", advanceRR.Code, advanceRR.Body.String())
	}
	if got := advanceRR.Header().Get("Location"); got != "/login/complete?flow_id=flow_mfa" {
		t.Fatalf("unexpected mfa redirect: %q", got)
	}

	got, err := flows.GetByID("flow_mfa")
	if err != nil {
		t.Fatalf("load flow: %v", err)
	}
	if got.State != string(flowengine.StateComplete) {
		t.Fatalf("expected complete state, got %q", got.State)
	}
}

func TestM2_InvalidTransitionsReturnConflict(t *testing.T) {
	router, users, flows := newFlowRouterForTest()
	seedUser(t, users, "usr_invalid", "totp", "normal")
	seedFlow(t, flows, "flow_invalid")

	verifyBeforePick := doJSON(t, router, http.MethodPost, "/api/v1/flows/flow_invalid/verify-mfa", map[string]string{
		"code": "123456",
	})
	if verifyBeforePick.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d body=%s", verifyBeforePick.Code, verifyBeforePick.Body.String())
	}
	if !strings.Contains(verifyBeforePick.Body.String(), "STATE_TRANSITION_INVALID") {
		t.Fatalf("expected STATE_TRANSITION_INVALID error, got %s", verifyBeforePick.Body.String())
	}

	expectedMismatch := doJSON(t, router, http.MethodPost, "/api/v1/flows/flow_invalid/select-user", map[string]string{
		"user_id":        "usr_invalid",
		"expected_state": "mfa_pending",
	})
	if expectedMismatch.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d body=%s", expectedMismatch.Code, expectedMismatch.Body.String())
	}
	if !strings.Contains(expectedMismatch.Body.String(), "STATE_TRANSITION_INVALID") {
		t.Fatalf("expected STATE_TRANSITION_INVALID error, got %s", expectedMismatch.Body.String())
	}
}

func TestM2_ScenarioInjectionBehavior(t *testing.T) {
	router, users, flows := newFlowRouterForTest()

	t.Run("account_locked_transitions_to_error", func(t *testing.T) {
		seedUser(t, users, "usr_locked", "totp", "account_locked")
		seedFlow(t, flows, "flow_locked")

		rr := doJSON(t, router, http.MethodPost, "/api/v1/flows/flow_locked/select-user", map[string]string{
			"user_id": "usr_locked",
		})
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
		}

		got, err := flows.GetByID("flow_locked")
		if err != nil {
			t.Fatalf("load flow: %v", err)
		}
		if got.State != string(flowengine.StateError) {
			t.Fatalf("expected error state, got %q", got.State)
		}
		if got.Error == "" {
			t.Fatalf("expected error message to be set")
		}
	})

	t.Run("mfa_fail_fails_first_attempt_then_succeeds", func(t *testing.T) {
		seedUser(t, users, "usr_mfafail", "totp", "mfa_fail")
		seedFlow(t, flows, "flow_mfafail")

		pick := doJSON(t, router, http.MethodPost, "/api/v1/flows/flow_mfafail/select-user", map[string]string{
			"user_id": "usr_mfafail",
		})
		if pick.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d body=%s", pick.Code, pick.Body.String())
		}

		first := doJSON(t, router, http.MethodPost, "/api/v1/flows/flow_mfafail/verify-mfa", map[string]string{
			"code": "123456",
		})
		if first.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 on first attempt, got %d body=%s", first.Code, first.Body.String())
		}

		second := doJSON(t, router, http.MethodPost, "/api/v1/flows/flow_mfafail/verify-mfa", map[string]string{
			"code": "123456",
		})
		if second.Code != http.StatusOK {
			t.Fatalf("expected 200 on second attempt, got %d body=%s", second.Code, second.Body.String())
		}
	})
}
