package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"authpilot/server/internal/domain"
	flowengine "authpilot/server/internal/flow"
	"authpilot/server/internal/store/memory"
)

// seedFlowAtState creates a flow already at the given state, with userID set.
func seedFlowAtState(t *testing.T, flows *memory.FlowStore, id, state, userID string) {
	t.Helper()
	now := time.Now().UTC()
	_, err := flows.Create(domain.Flow{
		ID:        id,
		State:     state,
		UserID:    userID,
		Scenario:  string(flowengine.ScenarioNormal),
		Protocol:  "oidc",
		CreatedAt: now,
		ExpiresAt: now.Add(30 * time.Minute),
	})
	if err != nil {
		t.Fatalf("seedFlowAtState: %v", err)
	}
}

func postJSON(router http.Handler, path string, body any) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

func assertCode(t *testing.T, rr *httptest.ResponseRecorder, wantStatus int, wantCode string) {
	t.Helper()
	if rr.Code != wantStatus {
		t.Errorf("HTTP status: want %d, got %d — body: %s", wantStatus, rr.Code, rr.Body.String())
		return
	}
	if wantCode == "" {
		return
	}
	var body map[string]any
	_ = json.NewDecoder(rr.Body).Decode(&body)
	errObj, _ := body["error"].(map[string]any)
	if errObj["code"] != wantCode {
		t.Errorf("error code: want %q, got %v", wantCode, errObj["code"])
	}
}

// ---------------------------------------------------------------------------
// select-user
// ---------------------------------------------------------------------------

func TestExpectedState_SelectUser_Match(t *testing.T) {
	router, users, flows := newFlowRouterForTest()
	seedUser(t, users, "u1", "none", "normal")
	seedFlow(t, flows, "f1")

	rr := postJSON(router, "/api/v1/flows/f1/select-user", map[string]any{
		"user_id":        "u1",
		"expected_state": "initiated",
	})
	assertCode(t, rr, http.StatusOK, "")
}

func TestExpectedState_SelectUser_Mismatch(t *testing.T) {
	router, users, flows := newFlowRouterForTest()
	seedUser(t, users, "u1", "none", "normal")
	seedFlow(t, flows, "f1") // state = initiated

	rr := postJSON(router, "/api/v1/flows/f1/select-user", map[string]any{
		"user_id":        "u1",
		"expected_state": "mfa_pending", // wrong
	})
	assertCode(t, rr, http.StatusConflict, "STATE_TRANSITION_INVALID")
}

func TestExpectedState_SelectUser_Omitted(t *testing.T) {
	// Omitting expected_state should behave exactly as before.
	router, users, flows := newFlowRouterForTest()
	seedUser(t, users, "u1", "none", "normal")
	seedFlow(t, flows, "f1")

	rr := postJSON(router, "/api/v1/flows/f1/select-user", map[string]any{
		"user_id": "u1",
	})
	assertCode(t, rr, http.StatusOK, "")
}

// ---------------------------------------------------------------------------
// verify-mfa
// ---------------------------------------------------------------------------

func TestExpectedState_VerifyMFA_Match(t *testing.T) {
	router, users, flows := newFlowRouterForTest()
	seedUser(t, users, "u1", "totp", "normal")
	seedFlowAtState(t, flows, "f1", string(flowengine.StateMFAPending), "u1")

	rr := postJSON(router, "/api/v1/flows/f1/verify-mfa", map[string]any{
		"code":           "123456",
		"expected_state": "mfa_pending",
	})
	assertCode(t, rr, http.StatusOK, "")
}

func TestExpectedState_VerifyMFA_Mismatch(t *testing.T) {
	router, users, flows := newFlowRouterForTest()
	seedUser(t, users, "u1", "totp", "normal")
	seedFlowAtState(t, flows, "f1", string(flowengine.StateMFAPending), "u1")

	rr := postJSON(router, "/api/v1/flows/f1/verify-mfa", map[string]any{
		"code":           "123456",
		"expected_state": "initiated", // wrong — flow is mfa_pending
	})
	assertCode(t, rr, http.StatusConflict, "STATE_TRANSITION_INVALID")
}

// ---------------------------------------------------------------------------
// approve
// ---------------------------------------------------------------------------

func TestExpectedState_Approve_Match(t *testing.T) {
	router, users, flows := newFlowRouterForTest()
	seedUser(t, users, "u1", "push", "normal")
	seedFlowAtState(t, flows, "f1", string(flowengine.StateMFAPending), "u1")

	rr := postJSON(router, "/api/v1/flows/f1/approve", map[string]any{
		"expected_state": "mfa_pending",
	})
	assertCode(t, rr, http.StatusOK, "")
}

func TestExpectedState_Approve_Mismatch(t *testing.T) {
	router, users, flows := newFlowRouterForTest()
	seedUser(t, users, "u1", "push", "normal")
	seedFlowAtState(t, flows, "f1", string(flowengine.StateMFAPending), "u1")

	rr := postJSON(router, "/api/v1/flows/f1/approve", map[string]any{
		"expected_state": "initiated", // wrong
	})
	assertCode(t, rr, http.StatusConflict, "STATE_TRANSITION_INVALID")
}

func TestExpectedState_Approve_Omitted(t *testing.T) {
	router, users, flows := newFlowRouterForTest()
	seedUser(t, users, "u1", "push", "normal")
	seedFlowAtState(t, flows, "f1", string(flowengine.StateMFAPending), "u1")

	rr := postJSON(router, "/api/v1/flows/f1/approve", map[string]any{})
	assertCode(t, rr, http.StatusOK, "")
}

// ---------------------------------------------------------------------------
// deny
// ---------------------------------------------------------------------------

func TestExpectedState_Deny_Match(t *testing.T) {
	router, _, flows := newFlowRouterForTest()
	seedFlowAtState(t, flows, "f1", string(flowengine.StateMFAPending), "u1")

	rr := postJSON(router, "/api/v1/flows/f1/deny", map[string]any{
		"expected_state": "mfa_pending",
	})
	assertCode(t, rr, http.StatusOK, "")
}

func TestExpectedState_Deny_Mismatch(t *testing.T) {
	router, _, flows := newFlowRouterForTest()
	seedFlowAtState(t, flows, "f1", string(flowengine.StateMFAPending), "u1")

	rr := postJSON(router, "/api/v1/flows/f1/deny", map[string]any{
		"expected_state": "complete", // wrong
	})
	assertCode(t, rr, http.StatusConflict, "STATE_TRANSITION_INVALID")
}

func TestExpectedState_Deny_Omitted(t *testing.T) {
	router, _, flows := newFlowRouterForTest()
	seedFlowAtState(t, flows, "f1", string(flowengine.StateMFAPending), "u1")

	rr := postJSON(router, "/api/v1/flows/f1/deny", map[string]any{})
	assertCode(t, rr, http.StatusOK, "")
}
