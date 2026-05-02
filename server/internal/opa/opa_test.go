package opa_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"

	"furnace/server/internal/config"
	"furnace/server/internal/domain"
	"furnace/server/internal/opa"
	"furnace/server/internal/store"
)

// newTestEngine returns an Engine with tight timeouts suitable for tests.
func newTestEngine(t *testing.T) *opa.Engine {
	t.Helper()
	cfg := config.OPAConfig{
		CompileTimeout: config.OPADefaultCompileTimeout,
		EvalTimeout:    config.OPADefaultEvalTimeout,
		MaxPolicyBytes: config.OPADefaultMaxPolicyBytes,
		MaxDataBytes:   config.OPADefaultMaxDataBytes,
		MaxBatchChecks: config.OPADefaultMaxBatchChecks,
		DecisionLog:    config.OPADecisionLogConfig{Enabled: false},
	}
	eng, err := opa.NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return eng
}

// newTestRouter returns an httptest.Server wired with the OPA routes (no policy store).
func newTestRouter(t *testing.T) *httptest.Server {
	t.Helper()
	eng := newTestEngine(t)
	root := mux.NewRouter()
	api := root.PathPrefix("/api/v1").Subrouter()
	opa.NewRouter(opa.RouterDeps{Engine: eng, Users: nil}, root, api)
	return httptest.NewServer(root)
}

// newTestRouterWithPolicies returns an httptest.Server wired with the OPA routes
// and an in-memory policy store for Policy Admin tests.
func newTestRouterWithPolicies(t *testing.T) (*httptest.Server, store.PolicyStore) {
	t.Helper()
	eng := newTestEngine(t)
	ps := newMemoryPolicyStore()
	root := mux.NewRouter()
	api := root.PathPrefix("/api/v1").Subrouter()
	opa.NewRouter(opa.RouterDeps{Engine: eng, Users: nil, Policies: ps}, root, api)
	return httptest.NewServer(root), ps
}

// memoryPolicyStore is a minimal in-memory PolicyStore for tests.
type memoryPolicyStore struct {
	mu       sync.Mutex
	policies map[string]domain.Policy
}

func newMemoryPolicyStore() *memoryPolicyStore {
	return &memoryPolicyStore{policies: make(map[string]domain.Policy)}
}

func (s *memoryPolicyStore) Create(p domain.Policy) (domain.Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies[p.ID] = p
	return p, nil
}

func (s *memoryPolicyStore) GetByID(id string) (domain.Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.policies[id]
	if !ok {
		return domain.Policy{}, store.ErrNotFound
	}
	return p, nil
}

func (s *memoryPolicyStore) GetByName(name string) (domain.Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.policies {
		if p.Name == name && p.Active {
			return p, nil
		}
	}
	return domain.Policy{}, store.ErrNotFound
}

func (s *memoryPolicyStore) List() ([]domain.Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]domain.Policy, 0, len(s.policies))
	for _, p := range s.policies {
		out = append(out, p)
	}
	return out, nil
}

func (s *memoryPolicyStore) Activate(id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	target, ok := s.policies[id]
	if !ok {
		return store.ErrNotFound
	}
	// Deactivate siblings with same name.
	for pid, p := range s.policies {
		if p.Name == target.Name {
			p.Active = false
			p.ActivatedAt = nil
			s.policies[pid] = p
		}
	}
	target.Active = true
	target.ActivatedAt = &at
	s.policies[id] = target
	return nil
}

func (s *memoryPolicyStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.policies[id]; !ok {
		return store.ErrNotFound
	}
	delete(s.policies, id)
	return nil
}

func postJSON(t *testing.T, srv *httptest.Server, path string, body any) *http.Response {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp, err := http.Post(srv.URL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

func decodeJSON(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Engine unit tests
// ---------------------------------------------------------------------------

func TestEval_Allow(t *testing.T) {
	eng := newTestEngine(t)
	result, err := eng.Eval(t.Context(), opa.EvalOptions{
		PolicyText: `package authz
default allow := false
allow if { input.user.role == "admin" }`,
		DataMap: map[string]any{},
		Input:   map[string]any{"user": map[string]any{"role": "admin"}},
	})
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if !result.Allow {
		t.Error("expected allow=true for admin role")
	}
	if !result.Defined {
		t.Error("expected result to be defined")
	}
}

func TestEval_Deny(t *testing.T) {
	eng := newTestEngine(t)
	result, err := eng.Eval(t.Context(), opa.EvalOptions{
		PolicyText: `package authz
default allow := false
allow if { input.user.role == "admin" }`,
		DataMap: map[string]any{},
		Input:   map[string]any{"user": map[string]any{"role": "viewer"}},
	})
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if result.Allow {
		t.Error("expected allow=false for viewer role")
	}
}

func TestEval_Undefined(t *testing.T) {
	eng := newTestEngine(t)
	result, err := eng.Eval(t.Context(), opa.EvalOptions{
		PolicyText: `package authz`,
		DataMap:    map[string]any{},
		Input:      map[string]any{},
		Query:      "data.authz.allow",
	})
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if result.Defined {
		t.Error("expected undefined result for policy with no allow rule")
	}
}

func TestEval_CompileError(t *testing.T) {
	eng := newTestEngine(t)
	_, err := eng.Eval(t.Context(), opa.EvalOptions{
		PolicyText: `this is not valid rego !!!`,
		DataMap:    map[string]any{},
		Input:      map[string]any{},
	})
	if err == nil {
		t.Fatal("expected compile error")
	}
	var ce *opa.CompileError
	if !isError(err, &ce) {
		t.Errorf("expected *CompileError, got %T: %v", err, err)
	}
}

func TestEval_WithTrace(t *testing.T) {
	eng := newTestEngine(t)
	result, err := eng.Eval(t.Context(), opa.EvalOptions{
		PolicyText: `package authz
default allow := false
allow if { input.x == 1 }`,
		DataMap:   map[string]any{},
		Input:     map[string]any{"x": 1},
		WithTrace: true,
	})
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if len(result.Trace) == 0 {
		t.Error("expected trace events when WithTrace=true")
	}
}

func TestEval_DisabledBuiltins(t *testing.T) {
	eng := newTestEngine(t)
	_, err := eng.Eval(t.Context(), opa.EvalOptions{
		PolicyText: `package authz
allow if {
	r := http.send({"method": "GET", "url": "http://example.com"})
	r.status_code == 200
}`,
		DataMap: map[string]any{},
		Input:   map[string]any{},
	})
	if err == nil {
		t.Fatal("expected compile error for disabled http.send builtin")
	}
}

func TestEval_DataStore(t *testing.T) {
	eng := newTestEngine(t)
	result, err := eng.Eval(t.Context(), opa.EvalOptions{
		PolicyText: `package authz
default allow := false
allow if {
	role := data.users[input.user_id].role
	role == "admin"
}`,
		DataMap: map[string]any{
			"users": map[string]any{
				"alice": map[string]any{"role": "admin"},
				"bob":   map[string]any{"role": "viewer"},
			},
		},
		Input: map[string]any{"user_id": "alice"},
	})
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if !result.Allow {
		t.Error("expected allow=true for alice (admin in data store)")
	}
}

// ---------------------------------------------------------------------------
// BuildInput
// ---------------------------------------------------------------------------

func TestBuildInput(t *testing.T) {
	raw := map[string]any{"user": map[string]any{"id": "u1"}}
	in := opa.BuildInput(raw, "read", "resource/posts", map[string]any{"env": "prod"})
	if in["action"] != "read" {
		t.Errorf("action: got %v", in["action"])
	}
	if in["resource"] != "resource/posts" {
		t.Errorf("resource: got %v", in["resource"])
	}
	if in["context"] == nil {
		t.Error("context missing")
	}
}

// ---------------------------------------------------------------------------
// ParseJWTClaims
// ---------------------------------------------------------------------------

func TestParseJWTClaims_Valid(t *testing.T) {
	// header.payload.sig — payload is {"sub":"u1","email":"u1@example.com"}
	token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiJ1MSIsImVtYWlsIjoidTFAZXhhbXBsZS5jb20ifQ." +
		"fakesig"
	claims, err := opa.ParseJWTClaims(token)
	if err != nil {
		t.Fatalf("ParseJWTClaims: %v", err)
	}
	if claims["sub"] != "u1" {
		t.Errorf("sub: got %v", claims["sub"])
	}
}

func TestParseJWTClaims_Invalid(t *testing.T) {
	_, err := opa.ParseJWTClaims("not.a.jwt.with.too.many.parts.oh.no")
	if err == nil {
		t.Fatal("expected error for malformed token")
	}
}

// ---------------------------------------------------------------------------
// HTTP handler tests
// ---------------------------------------------------------------------------

func TestHealthHandler(t *testing.T) {
	srv := newTestRouter(t)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/v1/opa/health")
	if err != nil {
		t.Fatalf("GET health: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
	var body opa.HealthResponse
	decodeJSON(t, resp, &body)
	if body.Status != "ok" {
		t.Errorf("status field: got %q", body.Status)
	}
	if body.Engine != "embedded" {
		t.Errorf("engine: got %q", body.Engine)
	}
}

func TestReadyHandler(t *testing.T) {
	srv := newTestRouter(t)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/v1/opa/health/ready")
	if err != nil {
		t.Fatalf("GET ready: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
}

func TestEvaluateHandler_Grant(t *testing.T) {
	srv := newTestRouter(t)
	defer srv.Close()

	body := opa.EvaluateRequest{
		Policy: `package authz
default allow := false
allow if { input.user.role == "admin" }`,
		Input:  map[string]any{"user": map[string]any{"role": "admin"}},
		Action: "read",
	}
	resp := postJSON(t, srv, "/api/v1/opa/evaluate", body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
	var out opa.EvaluateResponse
	decodeJSON(t, resp, &out)
	if !out.Allow {
		t.Error("expected allow=true")
	}
	if out.Decision != "grant" {
		t.Errorf("decision: got %q, want grant", out.Decision)
	}
}

func TestEvaluateHandler_Deny(t *testing.T) {
	srv := newTestRouter(t)
	defer srv.Close()

	body := opa.EvaluateRequest{
		Policy: `package authz
default allow := false
allow if { input.user.role == "admin" }`,
		Input: map[string]any{"user": map[string]any{"role": "viewer"}},
	}
	resp := postJSON(t, srv, "/api/v1/opa/evaluate", body)
	var out opa.EvaluateResponse
	decodeJSON(t, resp, &out)
	if out.Allow {
		t.Error("expected allow=false for viewer")
	}
	if out.Decision != "deny" {
		t.Errorf("decision: got %q, want deny", out.Decision)
	}
}

func TestEvaluateHandler_CompileError(t *testing.T) {
	srv := newTestRouter(t)
	defer srv.Close()

	body := opa.EvaluateRequest{
		Policy: `this is not rego !!!`,
		Input:  map[string]any{},
	}
	resp := postJSON(t, srv, "/api/v1/opa/evaluate", body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status: got %d, want 400", resp.StatusCode)
	}
}

func TestEvaluateHandler_MissingPolicy(t *testing.T) {
	srv := newTestRouter(t)
	defer srv.Close()

	body := map[string]any{"input": map[string]any{}}
	resp := postJSON(t, srv, "/api/v1/opa/evaluate", body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status: got %d, want 400", resp.StatusCode)
	}
}

func TestEvaluateHandler_WithTrace(t *testing.T) {
	srv := newTestRouter(t)
	defer srv.Close()

	body := opa.EvaluateRequest{
		Policy: `package authz
default allow := false
allow if { input.x == 1 }`,
		Input: map[string]any{"x": 1},
		Trace: true,
	}
	resp := postJSON(t, srv, "/api/v1/opa/evaluate", body)
	var out opa.EvaluateResponse
	decodeJSON(t, resp, &out)
	if len(out.Trace) == 0 {
		t.Error("expected trace events in response")
	}
}

func TestBatchHandler(t *testing.T) {
	srv := newTestRouter(t)
	defer srv.Close()

	body := opa.BatchRequest{
		Policy: `package authz
default allow := false
allow if { input.action == "read" }`,
		Checks: []opa.BatchCheck{
			{Action: "read", Resource: "posts"},
			{Action: "write", Resource: "posts"},
		},
	}
	resp := postJSON(t, srv, "/api/v1/opa/evaluate/batch", body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
	var out opa.BatchResponse
	decodeJSON(t, resp, &out)
	if out.TotalChecks != 2 {
		t.Errorf("total_checks: got %d, want 2", out.TotalChecks)
	}
	if out.Grant != 1 {
		t.Errorf("grant: got %d, want 1", out.Grant)
	}
	if out.Deny != 1 {
		t.Errorf("deny: got %d, want 1", out.Deny)
	}
}

func TestBatchHandler_EmptyChecks(t *testing.T) {
	srv := newTestRouter(t)
	defer srv.Close()

	body := opa.BatchRequest{
		Policy: `package authz
default allow := false`,
		Checks: []opa.BatchCheck{},
	}
	resp := postJSON(t, srv, "/api/v1/opa/evaluate/batch", body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status: got %d, want 400", resp.StatusCode)
	}
}

func TestValidateHandler_Valid(t *testing.T) {
	srv := newTestRouter(t)
	defer srv.Close()

	body := opa.ValidateRequest{
		Data: map[string]any{
			"permissions": map[string]any{
				"posts": map[string]any{
					"admin": map[string]any{
						"read":  "allow",
						"write": "allow",
					},
				},
			},
		},
	}
	resp := postJSON(t, srv, "/api/v1/opa/validate", body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
	var out opa.ValidateResponse
	decodeJSON(t, resp, &out)
	if !out.Valid {
		t.Errorf("expected valid=true, errors: %v", out.Errors)
	}
}

func TestValidateHandler_InvalidState(t *testing.T) {
	srv := newTestRouter(t)
	defer srv.Close()

	body := opa.ValidateRequest{
		Data: map[string]any{
			"permissions": map[string]any{
				"posts": map[string]any{
					"admin": map[string]any{
						"read": "yes_please", // invalid
					},
				},
			},
		},
	}
	resp := postJSON(t, srv, "/api/v1/opa/validate", body)
	var out opa.ValidateResponse
	decodeJSON(t, resp, &out)
	if out.Valid {
		t.Error("expected valid=false for invalid state value")
	}
	if len(out.Errors) == 0 {
		t.Error("expected at least one error")
	}
}

func TestDiffHandler_AddedRole(t *testing.T) {
	srv := newTestRouter(t)
	defer srv.Close()

	body := opa.DiffRequest{
		Before: map[string]any{
			"roles": map[string]any{"admin": map[string]any{"level": 1}},
		},
		After: map[string]any{
			"roles": map[string]any{
				"admin":     map[string]any{"level": 1},
				"superuser": map[string]any{"level": 2},
			},
		},
	}
	resp := postJSON(t, srv, "/api/v1/opa/diff", body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
	var out opa.DiffResponse
	decodeJSON(t, resp, &out)
	if len(out.AddedRoles) != 1 || out.AddedRoles[0] != "superuser" {
		t.Errorf("added_roles: got %v", out.AddedRoles)
	}
	if out.RecommendedBump != "major" {
		t.Errorf("recommended_bump: got %q, want major", out.RecommendedBump)
	}
}

func TestDiffHandler_NoDiff(t *testing.T) {
	srv := newTestRouter(t)
	defer srv.Close()

	data := map[string]any{
		"roles": map[string]any{"admin": map[string]any{"level": 1}},
	}
	body := opa.DiffRequest{Before: data, After: data}
	resp := postJSON(t, srv, "/api/v1/opa/diff", body)
	var out opa.DiffResponse
	decodeJSON(t, resp, &out)
	if out.RecommendedBump != "none" {
		t.Errorf("recommended_bump: got %q, want none", out.RecommendedBump)
	}
}

func TestTokenPipelineHandler_ValidTokens(t *testing.T) {
	srv := newTestRouter(t)
	defer srv.Close()

	// Minimal JWT with {"sub":"u1","role":"admin"} as payload.
	// header: {"alg":"none"}  payload: {"sub":"u1","role":"admin"}
	token := "eyJhbGciOiJub25lIn0." +
		"eyJzdWIiOiJ1MSIsInJvbGUiOiJhZG1pbiJ9." +
		"fakesig"

	body := opa.TokenPipelineRequest{
		Policy: `package authz
default allow := false
allow if { input.user.claims.role == "admin" }`,
		FurnaceToken: token,
		Action:       "read",
	}
	resp := postJSON(t, srv, "/api/v1/opa/evaluate/token-pipeline", body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
	var out opa.TokenPipelineResponse
	decodeJSON(t, resp, &out)
	if out.FurnaceResult == nil {
		t.Fatal("expected furnace_result")
	}
	if !out.FurnaceResult.Allow {
		t.Error("expected furnace_result.allow=true for admin role")
	}
}

func TestTokenPipelineHandler_MissingTokens(t *testing.T) {
	srv := newTestRouter(t)
	defer srv.Close()

	body := opa.TokenPipelineRequest{
		Policy: `package authz
default allow := false`,
	}
	resp := postJSON(t, srv, "/api/v1/opa/evaluate/token-pipeline", body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status: got %d, want 400", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Policy Admin
// ---------------------------------------------------------------------------

const testPolicy = `package authz
default allow := false
allow if { input.user.role == "admin" }`

func TestPolicyAdmin_CreateAndGet(t *testing.T) {
	srv, _ := newTestRouterWithPolicies(t)
	defer srv.Close()

	body := opa.PolicyCreateRequest{Name: "rbac", Version: "v1", Content: testPolicy}
	resp := postJSON(t, srv, "/api/v1/opa/policies", body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: got %d, want 201", resp.StatusCode)
	}
	var created opa.PolicyResponse
	decodeJSON(t, resp, &created)
	if created.ID == "" {
		t.Error("expected non-empty id")
	}
	if created.ContentHash == "" {
		t.Error("expected content_hash")
	}
	if created.Active {
		t.Error("expected active=false on create")
	}

	resp2, err := http.Get(srv.URL + "/api/v1/opa/policies/" + created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	var got opa.PolicyResponse
	decodeJSON(t, resp2, &got)
	if got.ID != created.ID {
		t.Errorf("id mismatch: got %q, want %q", got.ID, created.ID)
	}
}

func TestPolicyAdmin_List(t *testing.T) {
	srv, _ := newTestRouterWithPolicies(t)
	defer srv.Close()

	for _, name := range []string{"rbac", "abac"} {
		postJSON(t, srv, "/api/v1/opa/policies", opa.PolicyCreateRequest{
			Name: name, Version: "v1", Content: testPolicy,
		})
	}

	resp, err := http.Get(srv.URL + "/api/v1/opa/policies")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var out opa.PolicyListResponse
	decodeJSON(t, resp, &out)
	if out.Total != 2 {
		t.Errorf("total: got %d, want 2", out.Total)
	}
}

func TestPolicyAdmin_Activate(t *testing.T) {
	srv, _ := newTestRouterWithPolicies(t)
	defer srv.Close()

	var created opa.PolicyResponse
	decodeJSON(t, postJSON(t, srv, "/api/v1/opa/policies", opa.PolicyCreateRequest{
		Name: "rbac", Version: "v1", Content: testPolicy,
	}), &created)

	resp := postJSON(t, srv, "/api/v1/opa/policies/"+created.ID+"/activate", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("activate: got %d, want 200", resp.StatusCode)
	}
	var act opa.ActivateResponse
	decodeJSON(t, resp, &act)
	if !act.Active {
		t.Error("expected active=true after activation")
	}
	if act.ActivatedAt.IsZero() {
		t.Error("expected non-zero activated_at")
	}
}

func TestPolicyAdmin_ActivateDeactivatesSiblings(t *testing.T) {
	srv, _ := newTestRouterWithPolicies(t)
	defer srv.Close()

	var v1, v2 opa.PolicyResponse
	decodeJSON(t, postJSON(t, srv, "/api/v1/opa/policies", opa.PolicyCreateRequest{
		Name: "rbac", Version: "v1", Content: testPolicy,
	}), &v1)
	decodeJSON(t, postJSON(t, srv, "/api/v1/opa/policies", opa.PolicyCreateRequest{
		Name: "rbac", Version: "v2", Content: testPolicy,
	}), &v2)

	postJSON(t, srv, "/api/v1/opa/policies/"+v1.ID+"/activate", nil)
	postJSON(t, srv, "/api/v1/opa/policies/"+v2.ID+"/activate", nil)

	var got1, got2 opa.PolicyResponse
	decodeJSON(t, mustGet(t, srv.URL+"/api/v1/opa/policies/"+v1.ID), &got1)
	decodeJSON(t, mustGet(t, srv.URL+"/api/v1/opa/policies/"+v2.ID), &got2)
	if got1.Active {
		t.Error("v1 should be deactivated after v2 activated")
	}
	if !got2.Active {
		t.Error("v2 should be active")
	}
}

func TestPolicyAdmin_Delete(t *testing.T) {
	srv, _ := newTestRouterWithPolicies(t)
	defer srv.Close()

	var created opa.PolicyResponse
	decodeJSON(t, postJSON(t, srv, "/api/v1/opa/policies", opa.PolicyCreateRequest{
		Name: "rbac", Version: "v1", Content: testPolicy,
	}), &created)

	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/v1/opa/policies/"+created.ID, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("delete: got %d, want 204", resp.StatusCode)
	}

	resp2, _ := http.Get(srv.URL + "/api/v1/opa/policies/" + created.ID)
	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("after delete get: got %d, want 404", resp2.StatusCode)
	}
}

func TestPolicyAdmin_EvaluateByName(t *testing.T) {
	srv, _ := newTestRouterWithPolicies(t)
	defer srv.Close()

	// Create and activate a named policy.
	var created opa.PolicyResponse
	decodeJSON(t, postJSON(t, srv, "/api/v1/opa/policies", opa.PolicyCreateRequest{
		Name: "rbac", Version: "v1", Content: testPolicy,
	}), &created)
	postJSON(t, srv, "/api/v1/opa/policies/"+created.ID+"/activate", nil)

	// Evaluate using policy_name instead of inline policy.
	body := opa.EvaluateRequest{
		PolicyName: "rbac",
		Input:      map[string]any{"user": map[string]any{"role": "admin"}},
	}
	resp := postJSON(t, srv, "/api/v1/opa/evaluate", body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("evaluate by name: got %d, want 200", resp.StatusCode)
	}
	var out opa.EvaluateResponse
	decodeJSON(t, resp, &out)
	if !out.Allow {
		t.Error("expected allow=true for admin via named policy")
	}
}

func TestPolicyAdmin_CreateInvalidPolicy(t *testing.T) {
	srv, _ := newTestRouterWithPolicies(t)
	defer srv.Close()

	body := opa.PolicyCreateRequest{Name: "bad", Version: "v1", Content: "this is not rego !!!"}
	resp := postJSON(t, srv, "/api/v1/opa/policies", body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid rego, got %d", resp.StatusCode)
	}
}

func TestPolicyAdmin_GetNotFound(t *testing.T) {
	srv, _ := newTestRouterWithPolicies(t)
	defer srv.Close()

	resp, _ := http.Get(srv.URL + "/api/v1/opa/policies/pol_doesnotexist")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func mustGet(t *testing.T, url string) *http.Response {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return resp
}

// ---------------------------------------------------------------------------
// Concurrency: race-safe batch evaluation
// ---------------------------------------------------------------------------

func TestBatchHandler_Concurrent(t *testing.T) {
	srv := newTestRouter(t)
	defer srv.Close()

	checks := make([]opa.BatchCheck, 20)
	for i := range checks {
		checks[i] = opa.BatchCheck{Action: "read", Resource: "r"}
	}
	body := opa.BatchRequest{
		Policy: `package authz
default allow := false
allow if { input.action == "read" }`,
		Checks: checks,
	}
	resp := postJSON(t, srv, "/api/v1/opa/evaluate/batch", body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
	var out opa.BatchResponse
	decodeJSON(t, resp, &out)
	if out.TotalChecks != 20 {
		t.Errorf("total_checks: got %d, want 20", out.TotalChecks)
	}
	if out.Grant != 20 {
		t.Errorf("grant: got %d, want 20 (all reads should pass)", out.Grant)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// isError reports whether err is assignable to target (like errors.As but for
// tests where we check pointer types).
func isError[T error](err error, target *T) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "") && func() bool {
		_, ok := err.(T)
		return ok
	}()
}
