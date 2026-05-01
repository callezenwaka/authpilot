package opa_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"

	"furnace/server/internal/config"
	"furnace/server/internal/opa"
	"furnace/server/internal/tenant"
)

// --- Engine.BudgetFor unit tests ---

func engineWithBudgets(t *testing.T, tenantBudgets map[string]config.OPATenantBudget) *opa.Engine {
	t.Helper()
	cfg := config.OPAConfig{
		CompileTimeout: 2 * time.Second,
		EvalTimeout:    5 * time.Second,
		MaxPolicyBytes: 64 * 1024,
		MaxDataBytes:   5 * 1024 * 1024,
		MaxBatchChecks: 100,
		DecisionLog:    config.OPADecisionLogConfig{Enabled: false},
		TenantBudgets:  tenantBudgets,
	}
	eng, err := opa.NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return eng
}

func TestBudgetFor_GlobalOnlyWhenNoOverride(t *testing.T) {
	eng := engineWithBudgets(t, nil)
	b := eng.BudgetFor("acme")
	if b.EvalTimeout != 5*time.Second {
		t.Errorf("EvalTimeout: want 5s, got %v", b.EvalTimeout)
	}
	if b.MaxBatchChecks != 100 {
		t.Errorf("MaxBatchChecks: want 100, got %d", b.MaxBatchChecks)
	}
}

func TestBudgetFor_PerTenantTighterLimits(t *testing.T) {
	eng := engineWithBudgets(t, map[string]config.OPATenantBudget{
		"restricted": {
			EvalTimeout:    1 * time.Second,
			MaxPolicyBytes: 4 * 1024,
			MaxBatchChecks: 10,
		},
	})
	b := eng.BudgetFor("restricted")
	if b.EvalTimeout != 1*time.Second {
		t.Errorf("EvalTimeout: want 1s, got %v", b.EvalTimeout)
	}
	if b.MaxPolicyBytes != 4*1024 {
		t.Errorf("MaxPolicyBytes: want 4096, got %d", b.MaxPolicyBytes)
	}
	if b.MaxBatchChecks != 10 {
		t.Errorf("MaxBatchChecks: want 10, got %d", b.MaxBatchChecks)
	}
}

func TestBudgetFor_PerTenantCannotLoosenLimits(t *testing.T) {
	// Per-tenant values larger than global must be ignored.
	eng := engineWithBudgets(t, map[string]config.OPATenantBudget{
		"greedy": {
			EvalTimeout:    60 * time.Second, // larger than global 5s — must be ignored
			MaxBatchChecks: 9999,             // larger than global 100 — must be ignored
		},
	})
	b := eng.BudgetFor("greedy")
	if b.EvalTimeout != 5*time.Second {
		t.Errorf("EvalTimeout should stay at global 5s, got %v", b.EvalTimeout)
	}
	if b.MaxBatchChecks != 100 {
		t.Errorf("MaxBatchChecks should stay at global 100, got %d", b.MaxBatchChecks)
	}
}

func TestBudgetFor_UnknownTenantUsesGlobal(t *testing.T) {
	eng := engineWithBudgets(t, map[string]config.OPATenantBudget{
		"known": {EvalTimeout: 1 * time.Second},
	})
	b := eng.BudgetFor("unknown_tenant")
	if b.EvalTimeout != 5*time.Second {
		t.Errorf("unknown tenant should get global 5s EvalTimeout, got %v", b.EvalTimeout)
	}
}

func TestBudgetFor_PartialOverrideKeepsGlobalForUnset(t *testing.T) {
	// Only MaxBatchChecks is set; EvalTimeout/MaxPolicyBytes must stay global.
	eng := engineWithBudgets(t, map[string]config.OPATenantBudget{
		"partial": {MaxBatchChecks: 5},
	})
	b := eng.BudgetFor("partial")
	if b.MaxBatchChecks != 5 {
		t.Errorf("MaxBatchChecks: want 5, got %d", b.MaxBatchChecks)
	}
	if b.EvalTimeout != 5*time.Second {
		t.Errorf("EvalTimeout should remain global 5s, got %v", b.EvalTimeout)
	}
	if b.MaxPolicyBytes != 64*1024 {
		t.Errorf("MaxPolicyBytes should remain global 64 KiB, got %d", b.MaxPolicyBytes)
	}
}

// --- Handler enforcement tests ---

// routerWithBudget returns a test server where "restricted" tenant has
// tight limits: 100-byte policy cap, 5-item batch cap.
func routerWithBudget(t *testing.T) *httptest.Server {
	t.Helper()
	cfg := config.OPAConfig{
		CompileTimeout: config.OPADefaultCompileTimeout,
		EvalTimeout:    config.OPADefaultEvalTimeout,
		MaxPolicyBytes: config.OPADefaultMaxPolicyBytes,
		MaxDataBytes:   config.OPADefaultMaxDataBytes,
		MaxBatchChecks: config.OPADefaultMaxBatchChecks,
		DecisionLog:    config.OPADecisionLogConfig{Enabled: false},
		TenantBudgets: map[string]config.OPATenantBudget{
			"restricted": {
				MaxPolicyBytes: 100,
				MaxDataBytes:   200,
				MaxBatchChecks: 2,
			},
		},
	}
	eng, err := opa.NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	root := mux.NewRouter()
	// Inject tenant ID into context via middleware.
	root.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := tenant.WithTenant(r.Context(), "restricted")
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	api := root.PathPrefix("/api/v1").Subrouter()
	opa.NewRouter(opa.RouterDeps{Engine: eng}, root, api)
	return httptest.NewServer(root)
}

const smallPolicy = `package authz
default allow := false`

func TestEvaluateHandler_PolicyTooBig_PerTenant(t *testing.T) {
	srv := routerWithBudget(t)
	defer srv.Close()

	bigPolicy := strings.Repeat("# comment\n", 20) // > 100 bytes
	body, _ := json.Marshal(map[string]any{
		"policy": bigPolicy,
		"input":  map[string]any{"x": 1},
	})
	resp, err := http.Post(srv.URL+"/api/v1/opa/evaluate", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413, got %d", resp.StatusCode)
	}
}

func TestEvaluateHandler_PolicyWithinLimit_PerTenant(t *testing.T) {
	srv := routerWithBudget(t)
	defer srv.Close()

	body, _ := json.Marshal(map[string]any{
		"policy": smallPolicy, // < 100 bytes
		"input":  map[string]any{"x": 1},
	})
	resp, err := http.Post(srv.URL+"/api/v1/opa/evaluate", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestBatchHandler_TooManyChecks_PerTenant(t *testing.T) {
	srv := routerWithBudget(t)
	defer srv.Close()

	// Budget cap is 2; send 3.
	checks := []map[string]any{
		{"action": "read", "resource": "doc"},
		{"action": "write", "resource": "doc"},
		{"action": "delete", "resource": "doc"},
	}
	body, _ := json.Marshal(map[string]any{
		"policy": smallPolicy,
		"checks": checks,
	})
	resp, err := http.Post(srv.URL+"/api/v1/opa/evaluate/batch", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413, got %d", resp.StatusCode)
	}
}

func TestBatchHandler_WithinLimit_PerTenant(t *testing.T) {
	srv := routerWithBudget(t)
	defer srv.Close()

	checks := []map[string]any{
		{"action": "read", "resource": "doc"},
		{"action": "write", "resource": "doc"},
	}
	body, _ := json.Marshal(map[string]any{
		"policy": smallPolicy,
		"checks": checks,
	})
	resp, err := http.Post(srv.URL+"/api/v1/opa/evaluate/batch", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestEvaluateHandler_DataTooBig_PerTenant(t *testing.T) {
	srv := routerWithBudget(t)
	defer srv.Close()

	// Data byte cap is 200; send > 200 bytes of JSON data.
	bigData := map[string]any{"key": strings.Repeat("x", 250)}
	body, _ := json.Marshal(map[string]any{
		"policy": smallPolicy,
		"input":  map[string]any{"x": 1},
		"data":   bigData,
	})
	resp, err := http.Post(srv.URL+"/api/v1/opa/evaluate", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413, got %d", resp.StatusCode)
	}
}
