package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"authpilot/server/internal/domain"
	"authpilot/server/internal/store/memory"
)

// newWebAuthnRouter builds a minimal test router with a webauthn user seeded.
func newWebAuthnTestDeps() (http.Handler, *memory.FlowStore, *memory.UserStore) {
	users := memory.NewUserStore()
	flows := memory.NewFlowStore()
	u := domain.User{
		ID:        "usr_wa",
		Email:     "wa@example.com",
		MFAMethod: "webauthn",
		Active:    true,
	}
	if _, err := users.Create(u); err != nil {
		panic("seed webauthn user: " + err.Error())
	}
	router := NewRouter(Dependencies{
		Users:    users,
		Groups:   memory.NewGroupStore(),
		Flows:    flows,
		Sessions: memory.NewSessionStore(),
	})
	return router, flows, users
}

// decodeJSON is a test helper that fatalf on decode failure.
func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.NewDecoder(rec.Body).Decode(dst); err != nil {
		t.Fatalf("decode response JSON: %v", err)
	}
}

func TestSelectUser_WebAuthn_GoesToWebAuthnPending(t *testing.T) {
	router, flows, _ := newWebAuthnTestDeps()

	flowReq := httptest.NewRequest(http.MethodPost, "/api/v1/flows", nil)
	flowRec := httptest.NewRecorder()
	router.ServeHTTP(flowRec, flowReq)
	if flowRec.Code != http.StatusCreated {
		t.Fatalf("create flow: want 201, got %d", flowRec.Code)
	}
	var flow map[string]any
	decodeJSON(t, flowRec, &flow)
	flowID := flow["id"].(string)

	body := `{"user_id":"usr_wa"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/flows/"+flowID+"/select-user",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("select-user: want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var updated map[string]any
	decodeJSON(t, rec, &updated)
	if updated["state"] != "webauthn_pending" {
		t.Errorf("state: want webauthn_pending, got %v", updated["state"])
	}

	stored, _ := flows.GetByID(flowID)
	if stored.State != "webauthn_pending" {
		t.Errorf("stored state: want webauthn_pending, got %q", stored.State)
	}
}

func TestWebAuthnResponse_AdvancesToMFAApproved(t *testing.T) {
	router, flows, _ := newWebAuthnTestDeps()

	flowReq := httptest.NewRequest(http.MethodPost, "/api/v1/flows", nil)
	flowRec := httptest.NewRecorder()
	router.ServeHTTP(flowRec, flowReq)
	var flow map[string]any
	decodeJSON(t, flowRec, &flow)
	flowID := flow["id"].(string)

	selectReq := httptest.NewRequest(http.MethodPost, "/api/v1/flows/"+flowID+"/select-user",
		strings.NewReader(`{"user_id":"usr_wa"}`))
	selectReq.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(httptest.NewRecorder(), selectReq)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/flows/"+flowID+"/webauthn-response", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("webauthn-response: want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var updated map[string]any
	decodeJSON(t, rec, &updated)
	if updated["state"] != "mfa_approved" {
		t.Errorf("state: want mfa_approved, got %v", updated["state"])
	}

	stored, _ := flows.GetByID(flowID)
	if stored.State != "mfa_approved" {
		t.Errorf("stored state: want mfa_approved, got %q", stored.State)
	}
}

func TestWebAuthnResponse_WrongState_Returns409(t *testing.T) {
	router, _, _ := newWebAuthnTestDeps()

	flowReq := httptest.NewRequest(http.MethodPost, "/api/v1/flows", nil)
	flowRec := httptest.NewRecorder()
	router.ServeHTTP(flowRec, flowReq)
	var flow map[string]any
	decodeJSON(t, flowRec, &flow)
	flowID := flow["id"].(string)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/flows/"+flowID+"/webauthn-response", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("want 409, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestNotifications_WebAuthnPending_IncludesChallenge(t *testing.T) {
	router, flows, _ := newWebAuthnTestDeps()

	flowReq := httptest.NewRequest(http.MethodPost, "/api/v1/flows", nil)
	flowRec := httptest.NewRecorder()
	router.ServeHTTP(flowRec, flowReq)
	var flow map[string]any
	decodeJSON(t, flowRec, &flow)
	flowID := flow["id"].(string)

	selectReq := httptest.NewRequest(http.MethodPost, "/api/v1/flows/"+flowID+"/select-user",
		strings.NewReader(`{"user_id":"usr_wa"}`))
	selectReq.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(httptest.NewRecorder(), selectReq)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/notifications?flow_id="+flowID, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("notifications: want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var payload map[string]any
	decodeJSON(t, rec, &payload)
	if payload["type"] != "webauthn" {
		t.Errorf("type: want webauthn, got %v", payload["type"])
	}
	if payload["webauthn_challenge"] == "" || payload["webauthn_challenge"] == nil {
		t.Error("expected non-empty webauthn_challenge in notification payload")
	}
	if payload["webauthn_credential_id"] == "" || payload["webauthn_credential_id"] == nil {
		t.Error("expected webauthn_credential_id in notification payload")
	}

	stored, _ := flows.GetByID(flowID)
	if stored.WebAuthnChallenge == "" {
		t.Error("expected WebAuthnChallenge to be persisted on flow after notifications fetch")
	}
}

func TestAllNotifications_IncludesWebAuthnPending(t *testing.T) {
	router, _, _ := newWebAuthnTestDeps()

	flowReq := httptest.NewRequest(http.MethodPost, "/api/v1/flows", nil)
	flowRec := httptest.NewRecorder()
	router.ServeHTTP(flowRec, flowReq)
	var flow map[string]any
	decodeJSON(t, flowRec, &flow)
	flowID := flow["id"].(string)

	selectReq := httptest.NewRequest(http.MethodPost, "/api/v1/flows/"+flowID+"/select-user",
		strings.NewReader(`{"user_id":"usr_wa"}`))
	selectReq.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(httptest.NewRecorder(), selectReq)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/notifications/all", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("notifications/all: want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var payloads []map[string]any
	decodeJSON(t, rec, &payloads)
	found := false
	for _, p := range payloads {
		if p["flow_id"] == flowID && p["type"] == "webauthn" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected webauthn flow %q in /notifications/all", flowID)
	}
}

func TestExistingMFAMethods_Unaffected(t *testing.T) {
	cases := []struct {
		method        string
		expectedState string
	}{
		{"totp", "mfa_pending"},
		{"push", "mfa_pending"},
		{"sms", "mfa_pending"},
		{"magic_link", "mfa_pending"},
	}
	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			users := memory.NewUserStore()
			flows := memory.NewFlowStore()
			if _, err := users.Create(domain.User{
				ID: "usr_" + tc.method, Email: tc.method + "@example.com",
				MFAMethod: tc.method, Active: true,
			}); err != nil {
				t.Fatalf("seed user: %v", err)
			}
			router := NewRouter(Dependencies{
				Users:    users,
				Groups:   memory.NewGroupStore(),
				Flows:    flows,
				Sessions: memory.NewSessionStore(),
			})

			flowReq := httptest.NewRequest(http.MethodPost, "/api/v1/flows", nil)
			flowRec := httptest.NewRecorder()
			router.ServeHTTP(flowRec, flowReq)
			var flow map[string]any
			decodeJSON(t, flowRec, &flow)
			flowID := flow["id"].(string)

			body := `{"user_id":"usr_` + tc.method + `"}`
			req := httptest.NewRequest(http.MethodPost, "/api/v1/flows/"+flowID+"/select-user",
				strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("select-user: want 200, got %d", rec.Code)
			}
			var updated map[string]any
			decodeJSON(t, rec, &updated)
			if updated["state"] != tc.expectedState {
				t.Errorf("state: want %q, got %v", tc.expectedState, updated["state"])
			}
		})
	}
}
