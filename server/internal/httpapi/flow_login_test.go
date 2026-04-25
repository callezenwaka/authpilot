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

	"furnace/server/internal/domain"
	flowengine "furnace/server/internal/flow"
	"furnace/server/internal/store/memory"
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

// csrfTokenForFlow performs GET /login?flow_id=id, extracts and returns the CSRF
// cookie value, and the request cookie to send with subsequent POST requests.
func csrfTokenForFlow(t *testing.T, router http.Handler, flowID string) (cookieValue string, cookie *http.Cookie) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/login?flow_id="+flowID, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	for _, c := range rr.Result().Cookies() {
		if c.Name == "furnace_csrf" {
			return c.Value, c
		}
	}
	t.Fatal("furnace_csrf cookie not set by GET /login")
	return "", nil
}

func TestM2_MFAFlowCompletesThroughLoginPages(t *testing.T) {
	router, users, flows := newFlowRouterForTest()
	seedUser(t, users, "usr_totp", "totp", "normal")
	seedFlow(t, flows, "flow_mfa")

	// GET /login to obtain CSRF token.
	csrfVal, csrfCookie := csrfTokenForFlow(t, router, "flow_mfa")

	req := httptest.NewRequest(http.MethodPost, "/login/select-user?flow_id=flow_mfa",
		strings.NewReader(url.Values{"user_id": {"usr_totp"}, "csrf_token": {csrfVal}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrfCookie)
	pick := httptest.NewRecorder()
	router.ServeHTTP(pick, req)

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

func TestM16_CSRF_MissingOrInvalidToken_Returns403(t *testing.T) {
	router, users, flows := newFlowRouterForTest()
	seedUser(t, users, "usr_csrf", "none", "normal")
	seedFlow(t, flows, "flow_csrf")

	t.Run("no_cookie_no_token", func(t *testing.T) {
		rr := doForm(t, router, http.MethodPost, "/login/select-user?flow_id=flow_csrf", url.Values{
			"user_id": {"usr_csrf"},
		})
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d body=%s", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "CSRF_INVALID") {
			t.Fatalf("expected CSRF_INVALID, got %s", rr.Body.String())
		}
	})

	t.Run("cookie_present_but_wrong_form_token", func(t *testing.T) {
		csrfVal, csrfCookie := csrfTokenForFlow(t, router, "flow_csrf")
		_ = csrfVal
		req := httptest.NewRequest(http.MethodPost, "/login/select-user?flow_id=flow_csrf",
			strings.NewReader(url.Values{"user_id": {"usr_csrf"}, "csrf_token": {"wrongtoken"}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(csrfCookie)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d body=%s", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "CSRF_INVALID") {
			t.Fatalf("expected CSRF_INVALID, got %s", rr.Body.String())
		}
	})
}

func TestM2_CompletedAt_SetOnTerminalState(t *testing.T) {
	t.Run("complete_sets_completed_at", func(t *testing.T) {
		router, users, flows := newFlowRouterForTest()
		seedUser(t, users, "usr_cat1", "none", "normal")
		seedFlow(t, flows, "flow_cat1")

		rr := doJSON(t, router, http.MethodPost, "/api/v1/flows/flow_cat1/select-user", map[string]string{
			"user_id": "usr_cat1",
		})
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
		}
		got, _ := flows.GetByID("flow_cat1")
		if got.State != string(flowengine.StateComplete) {
			t.Fatalf("expected complete, got %q", got.State)
		}
		if got.CompletedAt == nil {
			t.Fatal("expected CompletedAt to be set on complete state")
		}
	})

	t.Run("mfa_denied_sets_completed_at", func(t *testing.T) {
		router, _, flows := newFlowRouterForTest()
		now := time.Now().UTC()
		_, err := flows.Create(domain.Flow{
			ID:        "flow_cat2",
			State:     string(flowengine.StateMFAPending),
			UserID:    "usr_cat2",
			Scenario:  string(flowengine.ScenarioNormal),
			Protocol:  "oidc",
			CreatedAt: now,
			ExpiresAt: now.Add(30 * time.Minute),
		})
		if err != nil {
			t.Fatalf("seed flow: %v", err)
		}

		rr := doJSON(t, router, http.MethodPost, "/api/v1/flows/flow_cat2/deny", map[string]string{})
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
		}
		got, _ := flows.GetByID("flow_cat2")
		if got.State != string(flowengine.StateMFADenied) {
			t.Fatalf("expected mfa_denied, got %q", got.State)
		}
		if got.CompletedAt == nil {
			t.Fatal("expected CompletedAt to be set on mfa_denied state")
		}
	})

	t.Run("in_progress_flow_has_nil_completed_at", func(t *testing.T) {
		_, _, flows := newFlowRouterForTest()
		seedFlow(t, flows, "flow_cat3")
		got, _ := flows.GetByID("flow_cat3")
		if got.CompletedAt != nil {
			t.Fatalf("expected CompletedAt to be nil for initiated flow, got %v", got.CompletedAt)
		}
	})
}

func TestM2_SlowMFA_StaysInMFAPendingThenAutoAdvances(t *testing.T) {
	router, users, flows := newFlowRouterForTest()
	seedUser(t, users, "usr_slow", "push", "slow_mfa")

	// Seed a flow whose CreatedAt is fresh — delay has NOT elapsed.
	nowFresh := time.Now().UTC()
	_, err := flows.Create(domain.Flow{
		ID:        "flow_slow_fresh",
		State:     string(flowengine.StateInitiated),
		Scenario:  string(flowengine.ScenarioSlowMFA),
		Protocol:  "oidc",
		CreatedAt: nowFresh,
		ExpiresAt: nowFresh.Add(30 * time.Minute),
	})
	if err != nil {
		t.Fatalf("seed flow: %v", err)
	}

	pick := doJSON(t, router, http.MethodPost, "/api/v1/flows/flow_slow_fresh/select-user", map[string]string{
		"user_id": "usr_slow",
	})
	if pick.Code != http.StatusOK {
		t.Fatalf("select-user: expected 200, got %d body=%s", pick.Code, pick.Body.String())
	}
	got, _ := flows.GetByID("flow_slow_fresh")
	if got.State != string(flowengine.StateMFAPending) {
		t.Fatalf("expected mfa_pending immediately after select-user, got %q", got.State)
	}

	// Now approve — flow is fresh, should return 202 (delay not elapsed).
	approve := doJSON(t, router, http.MethodPost, "/api/v1/flows/flow_slow_fresh/approve", map[string]string{})
	if approve.Code != http.StatusAccepted {
		t.Fatalf("approve during delay: expected 202, got %d body=%s", approve.Code, approve.Body.String())
	}

	// Seed a second flow with CreatedAt > 10s ago — delay HAS elapsed.
	nowOld := time.Now().UTC().Add(-15 * time.Second)
	_, err = flows.Create(domain.Flow{
		ID:        "flow_slow_old",
		State:     string(flowengine.StateMFAPending),
		UserID:    "usr_slow",
		Scenario:  string(flowengine.ScenarioSlowMFA),
		Protocol:  "oidc",
		CreatedAt: nowOld,
		ExpiresAt: nowOld.Add(30 * time.Minute),
	})
	if err != nil {
		t.Fatalf("seed old flow: %v", err)
	}

	// GET the flow — getAndAutoAdvanceFlow should advance it to mfa_approved.
	rr := doJSON(t, router, http.MethodGet, "/api/v1/flows/flow_slow_old", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("get flow: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var flowResp domain.Flow
	if err := json.NewDecoder(rr.Body).Decode(&flowResp); err != nil {
		t.Fatalf("decode flow: %v", err)
	}
	if flowResp.State != string(flowengine.StateMFAApproved) {
		t.Fatalf("expected mfa_approved after delay elapsed, got %q", flowResp.State)
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
