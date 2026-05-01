package httpapi

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"furnace/server/internal/authevents"
	"furnace/server/internal/store/memory"
)

func newMiddlewareRouter() http.Handler {
	return NewRouter(Dependencies{
		Users:     memory.NewUserStore(),
		Groups:    memory.NewGroupStore(),
		Flows:     memory.NewFlowStore(),
		Sessions:  memory.NewSessionStore(),
		RateLimit: 100,
	})
}

// --- OpenAPI ---

func TestOpenAPISpecHandler(t *testing.T) {
	r := newMiddlewareRouter()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "application/json") {
		t.Errorf("content-type = %q, want application/json", rec.Header().Get("Content-Type"))
	}
	// Must be valid JSON with openapi field.
	var spec map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &spec); err != nil {
		t.Fatalf("openapi.json is not valid JSON: %v", err)
	}
	if spec["openapi"] == nil {
		t.Error("expected 'openapi' field in spec")
	}
	if spec["paths"] == nil {
		t.Error("expected 'paths' field in spec")
	}
}

func TestOpenAPIDocsHandler(t *testing.T) {
	r := newMiddlewareRouter()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/docs", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "swagger") {
		t.Error("expected swagger UI reference in docs page")
	}
}

// --- Export ---

func TestExportHandlerSCIM(t *testing.T) {
	r := newMiddlewareRouter()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/export?format=scim", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "application/json") {
		t.Errorf("content-type = %q", rec.Header().Get("Content-Type"))
	}
	if rec.Header().Get("Content-Disposition") == "" {
		t.Error("expected Content-Disposition header")
	}
}

func TestExportHandlerOkta(t *testing.T) {
	r := newMiddlewareRouter()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/export?format=okta", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "text/csv") {
		t.Errorf("content-type = %q", rec.Header().Get("Content-Type"))
	}
}

func TestExportHandlerAzure(t *testing.T) {
	r := newMiddlewareRouter()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/export?format=azure", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestExportHandlerGoogle(t *testing.T) {
	r := newMiddlewareRouter()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/export?format=google", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestExportHandlerMissingFormat(t *testing.T) {
	r := newMiddlewareRouter()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/export", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestExportHandlerUnknownFormat(t *testing.T) {
	r := newMiddlewareRouter()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/export?format=nope", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// --- Rate limiting ---

func TestRateLimiter_AllowsUnderLimit(t *testing.T) {
	rl := NewRateLimiter(10, time.Minute)
	for i := 0; i < 10; i++ {
		if !rl.allow("127.0.0.1") {
			t.Errorf("request %d should be allowed", i+1)
		}
	}
}

func TestRateLimiter_BlocksOverLimit(t *testing.T) {
	rl := NewRateLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		rl.allow("10.0.0.1")
	}
	if rl.allow("10.0.0.1") {
		t.Error("4th request should be rate limited")
	}
}

func TestRateLimiter_IndependentPerIP(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute)
	rl.allow("1.1.1.1")
	rl.allow("1.1.1.1")
	if rl.allow("1.1.1.1") {
		t.Error("3rd request from 1.1.1.1 should be blocked")
	}
	// Different IP should still be allowed.
	if !rl.allow("2.2.2.2") {
		t.Error("request from 2.2.2.2 should be allowed")
	}
}

func TestRateLimitMiddleware_Returns429(t *testing.T) {
	rl := NewRateLimiter(1, time.Minute)
	handler := rateLimitMiddleware(rl, nil, authevents.Noop())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request — should pass.
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.RemoteAddr = "5.5.5.5:1234"
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Errorf("first request status = %d, want 200", rec1.Code)
	}

	// Second request — should be rate limited.
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "5.5.5.5:1235"
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Errorf("second request status = %d, want 429", rec2.Code)
	}
}

func TestRateLimitMiddleware_HeadersOn429(t *testing.T) {
	rl := NewRateLimiter(1, time.Minute)
	handler := rateLimitMiddleware(rl, nil, authevents.Noop())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	makeReq := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
		req.RemoteAddr = "6.6.6.6:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	makeReq() // exhaust the one token

	rec := makeReq() // this one is rate-limited
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rec.Code)
	}
	for _, hdr := range []string{"Retry-After", "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"} {
		if rec.Header().Get(hdr) == "" {
			t.Errorf("missing header %q on 429 response", hdr)
		}
	}
	if rec.Header().Get("X-RateLimit-Remaining") != "0" {
		t.Errorf("X-RateLimit-Remaining want 0, got %q", rec.Header().Get("X-RateLimit-Remaining"))
	}
}

func TestRateLimitMiddleware_HeadersOnAllowedRequest(t *testing.T) {
	rl := NewRateLimiter(10, time.Minute)
	handler := rateLimitMiddleware(rl, nil, authevents.Noop())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	req.RemoteAddr = "7.7.7.7:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if rec.Header().Get("X-RateLimit-Limit") != "10" {
		t.Errorf("X-RateLimit-Limit want 10, got %q", rec.Header().Get("X-RateLimit-Limit"))
	}
	if rec.Header().Get("X-RateLimit-Reset") == "" {
		t.Error("X-RateLimit-Reset should be present on allowed request")
	}
}

// --- Idempotency ---

func TestIdempotencyMiddleware_CachesResponse(t *testing.T) {
	store := newIdempotencyStore(5 * time.Minute)
	calls := 0
	handler := idempotencyMiddleware(store)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"u1"}`))
	}))

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(`{}`))
		req.Header.Set("Idempotency-Key", "key-abc")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusCreated {
			t.Errorf("request %d: status = %d, want 201", i+1, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "u1") {
			t.Errorf("request %d: unexpected body: %s", i+1, rec.Body.String())
		}
	}

	// Handler should only have been called once.
	if calls != 1 {
		t.Errorf("handler called %d times, want 1", calls)
	}
}

func TestIdempotencyMiddleware_ReplayHeader(t *testing.T) {
	store := newIdempotencyStore(5 * time.Minute)
	handler := idempotencyMiddleware(store)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))

	makeReq := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/groups", strings.NewReader(`{}`))
		req.Header.Set("Idempotency-Key", "key-xyz")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	makeReq() // first — no replay header
	rec2 := makeReq()
	if rec2.Header().Get("Idempotent-Replayed") != "true" {
		t.Error("expected Idempotent-Replayed: true on second request")
	}
}

func TestIdempotencyMiddleware_SkipsNonPost(t *testing.T) {
	store := newIdempotencyStore(5 * time.Minute)
	calls := 0
	handler := idempotencyMiddleware(store)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
		req.Header.Set("Idempotency-Key", "key-get")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		_ = rec
	}

	if calls != 3 {
		t.Errorf("GET requests should not be cached; handler called %d times, want 3", calls)
	}
}

func TestIdempotencyMiddleware_DifferentKeys(t *testing.T) {
	store := newIdempotencyStore(5 * time.Minute)
	calls := 0
	handler := idempotencyMiddleware(store)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusCreated)
	}))

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(`{}`))
		req.Header.Set("Idempotency-Key", "key-unique-"+string(rune('A'+i)))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		_ = rec
	}

	if calls != 3 {
		t.Errorf("different keys should not share cache; handler called %d times, want 3", calls)
	}
}

// --- clientIP / trusted-proxy XFF gating ---

func TestClientIP_XFFIgnoredWhenNoTrustedProxies(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.5:54321"
	r.Header.Set("X-Forwarded-For", "10.10.10.10")
	if got := clientIP(r, nil); got != "203.0.113.5" {
		t.Errorf("XFF must be ignored without a trusted-proxy CIDR; got %q want 203.0.113.5", got)
	}
}

func TestClientIP_XFFHonouredWhenRemoteIsTrusted(t *testing.T) {
	_, cidr, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.7:54321"
	r.Header.Set("X-Forwarded-For", "203.0.113.42, 10.0.0.7")
	if got := clientIP(r, []*net.IPNet{cidr}); got != "203.0.113.42" {
		t.Errorf("XFF should be honoured behind a trusted proxy; got %q want 203.0.113.42", got)
	}
}

func TestClientIP_XFFIgnoredWhenRemoteNotTrusted(t *testing.T) {
	_, cidr, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.99:54321" // NOT in the trusted CIDR
	r.Header.Set("X-Forwarded-For", "10.10.10.10")
	if got := clientIP(r, []*net.IPNet{cidr}); got != "203.0.113.99" {
		t.Errorf("XFF must be ignored when RemoteAddr is outside trusted CIDR; got %q want 203.0.113.99", got)
	}
}

// --- requestIsHTTPS / behind-proxy TLS detection ---

func TestRequestIsHTTPS_DirectTLS(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.TLS = &tls.ConnectionState{} // simulate direct TLS termination
	if !requestIsHTTPS(r, nil) {
		t.Error("direct TLS connections must be reported as HTTPS")
	}
}

func TestRequestIsHTTPS_NoProxiesIgnoresXFP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.5:54321"
	r.Header.Set("X-Forwarded-Proto", "https") // spoofable when no proxy gate
	if requestIsHTTPS(r, nil) {
		t.Error("X-Forwarded-Proto must be ignored without a trusted-proxy CIDR")
	}
}

func TestRequestIsHTTPS_TrustedProxyXFPHonoured(t *testing.T) {
	_, cidr, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.7:54321"
	r.Header.Set("X-Forwarded-Proto", "https")
	if !requestIsHTTPS(r, []*net.IPNet{cidr}) {
		t.Error("X-Forwarded-Proto: https from trusted proxy must mark request HTTPS")
	}
}

func TestRequestIsHTTPS_UntrustedProxyXFPIgnored(t *testing.T) {
	_, cidr, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.99:54321" // NOT in the trusted CIDR
	r.Header.Set("X-Forwarded-Proto", "https")
	if requestIsHTTPS(r, []*net.IPNet{cidr}) {
		t.Error("X-Forwarded-Proto must be ignored when RemoteAddr is outside trusted CIDR")
	}
}

func TestRequestIsHTTPS_TrustedProxyHTTPNotSecure(t *testing.T) {
	_, cidr, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.7:54321"
	r.Header.Set("X-Forwarded-Proto", "http")
	if requestIsHTTPS(r, []*net.IPNet{cidr}) {
		t.Error("trusted proxy reporting plain HTTP must not be treated as HTTPS")
	}
}
