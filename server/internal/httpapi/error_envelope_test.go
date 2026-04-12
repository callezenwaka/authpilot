package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func assertErrorEnvelope(t *testing.T, rec *httptest.ResponseRecorder, wantStatus int, wantCode string) map[string]any {
	t.Helper()
	if rec.Code != wantStatus {
		t.Errorf("HTTP status: want %d, got %d — body: %s", wantStatus, rec.Code, rec.Body.String())
	}
	var env map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	errObj, _ := env["error"].(map[string]any)
	if errObj == nil {
		t.Fatal("envelope missing 'error' object")
	}
	if errObj["code"] != wantCode {
		t.Errorf("error.code: want %q, got %v", wantCode, errObj["code"])
	}
	return errObj
}

// ---------------------------------------------------------------------------
// docs_url present on all errors
// ---------------------------------------------------------------------------

func TestErrorEnvelope_DocsURL_Present(t *testing.T) {
	router, _, _ := newFlowRouterForTest()

	// Trigger a known error — flow not found.
	rec := doJSON(t, router, http.MethodGet, "/api/v1/flows/nonexistent", nil)
	errObj := assertErrorEnvelope(t, rec, http.StatusNotFound, "not_found")

	docsURL, _ := errObj["docs_url"].(string)
	if docsURL == "" {
		t.Error("error.docs_url should be present")
	}
	if !strings.Contains(docsURL, "not_found") {
		t.Errorf("docs_url should reference the error code, got %q", docsURL)
	}
}

// ---------------------------------------------------------------------------
// details populated on flow-not-found (spec exit criterion)
// ---------------------------------------------------------------------------

func TestErrorEnvelope_Details_FlowNotFound(t *testing.T) {
	router, _, _ := newFlowRouterForTest()

	rec := doJSON(t, router, http.MethodGet, "/api/v1/flows/missing-flow-id", nil)
	errObj := assertErrorEnvelope(t, rec, http.StatusNotFound, "not_found")

	details, _ := errObj["details"].(map[string]any)
	if details == nil {
		t.Fatal("error.details should be present for flow-not-found")
	}
	if details["flow_id"] != "missing-flow-id" {
		t.Errorf("details.flow_id: want %q, got %v", "missing-flow-id", details["flow_id"])
	}
}

// ---------------------------------------------------------------------------
// docs_url present on rate-limit error
// ---------------------------------------------------------------------------

func TestErrorEnvelope_DocsURL_OnRateLimit(t *testing.T) {
	rl := NewRateLimiter(1, 0) // window=0 means immediate refill — exhaust manually
	// Use a tiny limiter and exhaust it.
	rl2 := NewRateLimiter(1, 60_000_000_000) // 1 req / minute
	handler := rateLimitMiddleware(rl2)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	_ = rl

	makeReq := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "9.9.9.9:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	makeReq() // allow first

	rec := makeReq() // rate limited
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rec.Code)
	}

	var env map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&env)
	errObj, _ := env["error"].(map[string]any)
	if errObj["docs_url"] == nil {
		t.Error("docs_url should be present on rate-limit error")
	}
}
