package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"authpilot/server/internal/store/memory"
)

// fakeConfigPatcher implements ConfigPatcher for tests.
type fakeConfigPatcher struct {
	ttls TokenTTLs
}

func newFakePatcher() *fakeConfigPatcher {
	at, id, rt := 3600, 3600, 86400
	return &fakeConfigPatcher{ttls: TokenTTLs{
		AccessTokenTTL:  &at,
		IDTokenTTL:      &id,
		RefreshTokenTTL: &rt,
	}}
}

func (f *fakeConfigPatcher) GetTokenTTLs() TokenTTLs { return f.ttls }
func (f *fakeConfigPatcher) SetTokenTTLs(t TokenTTLs) error {
	if t.AccessTokenTTL != nil {
		v := *t.AccessTokenTTL
		f.ttls.AccessTokenTTL = &v
	}
	if t.IDTokenTTL != nil {
		v := *t.IDTokenTTL
		f.ttls.IDTokenTTL = &v
	}
	if t.RefreshTokenTTL != nil {
		v := *t.RefreshTokenTTL
		f.ttls.RefreshTokenTTL = &v
	}
	return nil
}

func newConfigTestRouter(cp ConfigPatcher) http.Handler {
	return NewRouter(Dependencies{
		Users:         memory.NewUserStore(),
		Groups:        memory.NewGroupStore(),
		Flows:         memory.NewFlowStore(),
		Sessions:      memory.NewSessionStore(),
		ConfigPatcher: cp,
	})
}

// ---------------------------------------------------------------------------

func TestConfig_GET(t *testing.T) {
	router := newConfigTestRouter(newFakePatcher())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&body)
	tokens, _ := body["tokens"].(map[string]any)
	if tokens["access_token_ttl"] == nil {
		t.Error("expected access_token_ttl in GET /config response")
	}
}

func TestConfig_PATCH_UpdatesTokenTTL(t *testing.T) {
	cp := newFakePatcher()
	router := newConfigTestRouter(cp)

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/config",
		strings.NewReader(`{"tokens":{"access_token_ttl":7200}}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if *cp.ttls.AccessTokenTTL != 7200 {
		t.Errorf("access_token_ttl: want 7200, got %d", *cp.ttls.AccessTokenTTL)
	}
}

func TestConfig_PATCH_RestartRequiredFields(t *testing.T) {
	cases := []string{
		`{"http_addr":":9999"}`,
		`{"protocol_addr":":9998"}`,
		`{"issuer_url":"http://other"}`,
	}
	for _, body := range cases {
		router := newConfigTestRouter(newFakePatcher())
		req := httptest.NewRequest(http.MethodPatch, "/api/v1/config", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("body=%s: expected 400, got %d", body, rec.Code)
			continue
		}
		var resp map[string]any
		_ = json.NewDecoder(rec.Body).Decode(&resp)
		errObj, _ := resp["error"].(map[string]any)
		if errObj["code"] != "RESTART_REQUIRED" {
			t.Errorf("body=%s: expected RESTART_REQUIRED, got %v", body, errObj["code"])
		}
		if errObj["restart_required"] != true {
			t.Errorf("body=%s: expected restart_required=true", body)
		}
	}
}

func TestConfig_PATCH_NilPatcher_Returns501(t *testing.T) {
	router := newConfigTestRouter(nil)

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/config", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotImplemented {
		t.Errorf("expected 501, got %d", rec.Code)
	}
}

func TestConfig_GET_NilPatcher_Returns501(t *testing.T) {
	router := newConfigTestRouter(nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotImplemented {
		t.Errorf("expected 501, got %d", rec.Code)
	}
}
