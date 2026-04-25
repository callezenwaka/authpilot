package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"furnace/server/internal/store/memory"
)

// makeJWT builds a minimal unsigned JWT with the given claims (base64url-encoded
// JSON). The signature part is a placeholder — this is a dev tool and no
// verification is performed.
func makeJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	b64 := base64.RawURLEncoding.EncodeToString
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	header := b64([]byte(`{"alg":"RS256","typ":"JWT"}`))
	body := b64(payload)
	return header + "." + body + ".sig"
}

func newDebugRouter(t *testing.T) http.Handler {
	t.Helper()
	return NewRouter(Dependencies{
		Users:    memory.NewUserStore(),
		Groups:   memory.NewGroupStore(),
		Flows:    memory.NewFlowStore(),
		Sessions: memory.NewSessionStore(),
		APIKey:   "test-key",
	})
}

func TestTokenCompare_MissingFurnaceToken(t *testing.T) {
	r := newDebugRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/debug/token-compare?provider_token=abc", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestTokenCompare_MissingProviderToken(t *testing.T) {
	r := newDebugRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/debug/token-compare?furnace_token=abc", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestTokenCompare_InvalidJWT(t *testing.T) {
	r := newDebugRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/debug/token-compare?furnace_token=notajwt&provider_token=notajwt", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", rr.Code)
	}
}

func TestTokenCompare_IdenticalTokens_NoDiff(t *testing.T) {
	claims := map[string]any{"sub": "u1", "email": "a@b.com"}
	tok := makeJWT(t, claims)

	r := newDebugRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/debug/token-compare?furnace_token="+tok+"&provider_token="+tok, nil)
	req.Header.Set("Authorization", "Bearer test-key")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	diffs, ok := resp["differences"].([]any)
	if !ok {
		t.Fatalf("expected differences array, got %T", resp["differences"])
	}
	if len(diffs) != 0 {
		t.Fatalf("expected 0 diffs for identical tokens, got %d", len(diffs))
	}
}

func TestTokenCompare_DifferentClaims_ReturnsDiff(t *testing.T) {
	furnaceClaims := map[string]any{"sub": "u1", "email": "a@b.com", "name": "Alice"}
	// Simulated Azure AD token: email renamed to preferred_username, tid added
	providerClaims := map[string]any{"sub": "u1", "preferred_username": "a@b.com", "name": "Alice", "tid": "common"}

	apTok := makeJWT(t, furnaceClaims)
	pvTok := makeJWT(t, providerClaims)

	r := newDebugRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/debug/token-compare?furnace_token="+apTok+"&provider_token="+pvTok, nil)
	req.Header.Set("Authorization", "Bearer test-key")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	diffs, ok := resp["differences"].([]any)
	if !ok {
		t.Fatalf("expected differences array, got %T", resp["differences"])
	}
	// email present in furnace, missing in provider
	// preferred_username missing in furnace, present in provider
	// tid missing in furnace, present in provider
	if len(diffs) == 0 {
		t.Fatal("expected diffs between furnace and azure tokens")
	}
}

func TestTokenCompare_UnknownFlowID_Returns404(t *testing.T) {
	claims := map[string]any{"sub": "u1"}
	tok := makeJWT(t, claims)

	r := newDebugRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/debug/token-compare?furnace_token="+tok+"&provider_token="+tok+"&flow_id=no-such-flow", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

// diffClaims unit tests

func TestDiffClaims_Empty(t *testing.T) {
	diffs := diffClaims(map[string]any{}, map[string]any{})
	if len(diffs) != 0 {
		t.Fatalf("expected no diffs, got %d", len(diffs))
	}
}

func TestDiffClaims_MissingInProvider(t *testing.T) {
	diffs := diffClaims(map[string]any{"email": "a@b.com"}, map[string]any{})
	if len(diffs) != 1 {
		t.Fatalf("expected 1 diff, got %d", len(diffs))
	}
	if diffs[0].Path != "email" {
		t.Fatalf("expected path=email, got %s", diffs[0].Path)
	}
}

func TestDiffClaims_MissingInFurnace(t *testing.T) {
	diffs := diffClaims(map[string]any{}, map[string]any{"tid": "common"})
	if len(diffs) != 1 {
		t.Fatalf("expected 1 diff, got %d", len(diffs))
	}
	if diffs[0].Path != "tid" {
		t.Fatalf("expected path=tid, got %s", diffs[0].Path)
	}
}

func TestDiffClaims_ValueDiffers(t *testing.T) {
	diffs := diffClaims(map[string]any{"sub": "u1"}, map[string]any{"sub": "u2"})
	if len(diffs) != 1 {
		t.Fatalf("expected 1 diff, got %d", len(diffs))
	}
	if diffs[0].Note != "values differ" {
		t.Fatalf("expected note 'values differ', got %s", diffs[0].Note)
	}
}

func TestDiffClaims_NestedValueDiffers(t *testing.T) {
	furnace := map[string]any{
		"address": map[string]any{"street_address": "123 Main St", "city": "Springfield"},
	}
	provider := map[string]any{
		"address": map[string]any{"street_address": "456 Oak Ave", "city": "Springfield"},
	}
	diffs := diffClaims(furnace, provider)
	if len(diffs) != 1 {
		t.Fatalf("expected 1 diff, got %d: %v", len(diffs), diffs)
	}
	if diffs[0].Path != "address.street_address" {
		t.Fatalf("expected path=address.street_address, got %s", diffs[0].Path)
	}
	if diffs[0].Note != "values differ" {
		t.Fatalf("expected note 'values differ', got %s", diffs[0].Note)
	}
}

func TestDiffClaims_NestedKeyMissing(t *testing.T) {
	furnace := map[string]any{
		"address": map[string]any{"street_address": "123 Main St", "postal_code": "12345"},
	}
	provider := map[string]any{
		"address": map[string]any{"street_address": "123 Main St"},
	}
	diffs := diffClaims(furnace, provider)
	if len(diffs) != 1 {
		t.Fatalf("expected 1 diff, got %d: %v", len(diffs), diffs)
	}
	if diffs[0].Path != "address.postal_code" {
		t.Fatalf("expected path=address.postal_code, got %s", diffs[0].Path)
	}
}

func TestDiffClaims_TypeMismatch_StringVsArray(t *testing.T) {
	furnace := map[string]any{"roles": "admin"}
	provider := map[string]any{"roles": []any{"admin", "user"}}
	diffs := diffClaims(furnace, provider)
	if len(diffs) != 1 {
		t.Fatalf("expected 1 diff, got %d: %v", len(diffs), diffs)
	}
	if diffs[0].Path != "roles" {
		t.Fatalf("expected path=roles, got %s", diffs[0].Path)
	}
	if diffs[0].Note != "type mismatch: furnace has string, provider has array" {
		t.Fatalf("unexpected note: %s", diffs[0].Note)
	}
}

func TestDiffClaims_TypeMismatch_NumberVsString(t *testing.T) {
	furnace := map[string]any{"exp": float64(1700000000)}
	provider := map[string]any{"exp": "1700000000"}
	diffs := diffClaims(furnace, provider)
	if len(diffs) != 1 {
		t.Fatalf("expected 1 diff, got %d: %v", len(diffs), diffs)
	}
	if diffs[0].Note != "type mismatch: furnace has number, provider has string" {
		t.Fatalf("unexpected note: %s", diffs[0].Note)
	}
}
