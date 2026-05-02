package opa

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"furnace/server/internal/config"
)

// newTenantDecisionLog builds a decisionLog with per-tenant budgets wired in.
func newTenantDecisionLog(t *testing.T, cfg config.OPADecisionLogConfig, budgets map[string]config.OPATenantBudget) *decisionLog {
	t.Helper()
	dl, err := newDecisionLog(cfg, budgets)
	if err != nil {
		t.Fatalf("newDecisionLog: %v", err)
	}
	t.Cleanup(func() { _ = dl.Close() })
	return dl
}

// newBufDecisionLog returns a decisionLog that writes to a strings.Builder,
// suitable for capturing output in per-tenant write() tests.
func newBufDecisionLog(cfg config.OPADecisionLogConfig) (*decisionLog, *strings.Builder) {
	var buf strings.Builder
	dl := &decisionLog{cfg: cfg}
	dl.w = writerFunc(func(p []byte) (int, error) { buf.Write(p); return len(p), nil })
	dl.enc = json.NewEncoder(dl.w)
	return dl, &buf
}

// --- per-tenant redaction ---

func TestDecisionLog_TenantAdditionalRedactFields(t *testing.T) {
	dl, buf := newBufDecisionLog(config.OPADecisionLogConfig{
		Enabled:      true,
		IncludeInput: true,
		RedactFields: []string{"user.claims.password"}, // global only
	})

	entry := baseEntry()
	entry.TenantID = "tenant_a"
	entry.TenantOverrides = &config.OPATenantDecisionLog{
		AdditionalRedactFields: []string{"user.claims.email"}, // tenant adds email
	}
	dl.write(entry)

	body := buf.String()
	if strings.Contains(body, "hunter2") {
		t.Error("global redact field (password) leaked into decision log")
	}
	if strings.Contains(body, "alice@example.com") {
		t.Error("per-tenant redact field (email) leaked into decision log")
	}
	if !strings.Contains(body, "usr_1") {
		t.Error("sub should not be redacted")
	}
}

func TestDecisionLog_TenantRedact_OriginalInputUnmodified(t *testing.T) {
	dl, _ := newBufDecisionLog(config.OPADecisionLogConfig{
		Enabled:      true,
		IncludeInput: true,
	})

	entry := baseEntry()
	origEmail := entry.Input["user"].(map[string]any)["claims"].(map[string]any)["email"]
	entry.TenantOverrides = &config.OPATenantDecisionLog{
		AdditionalRedactFields: []string{"user.claims.email"},
	}
	dl.write(entry)

	afterEmail := entry.Input["user"].(map[string]any)["claims"].(map[string]any)["email"]
	if afterEmail != origEmail {
		t.Errorf("write() mutated caller's Input: got %v", afterEmail)
	}
}

// --- per-tenant scrub ---

func TestDecisionLog_TenantScrubEnablesWhenGlobalDisabled(t *testing.T) {
	dl, buf := newBufDecisionLog(config.OPADecisionLogConfig{
		Enabled:                true,
		IncludePolicy:          true,
		ScrubPolicyCredentials: false, // global off
	})

	entry := baseEntry()
	entry.Policy = `package authz
# token = "eyJhbGciOiJSUzI1NiJ9eyJzdWIiOiJ1c3JfMSJ9signature1"
default allow := false`
	entry.TenantOverrides = &config.OPATenantDecisionLog{
		ScrubPolicyCredentials: true, // per-tenant on
	}
	dl.write(entry)

	if strings.Contains(buf.String(), "eyJhbGciOiJSUzI1NiJ9eyJzdWIiOiJ1c3JfMSJ9signature1") {
		t.Error("credential not scrubbed despite per-tenant ScrubPolicyCredentials=true")
	}
}

func TestDecisionLog_TenantScrubOff_GlobalScrubStillApplies(t *testing.T) {
	dl, buf := newBufDecisionLog(config.OPADecisionLogConfig{
		Enabled:                true,
		IncludePolicy:          true,
		ScrubPolicyCredentials: true, // global on
	})

	entry := baseEntry()
	entry.Policy = `package authz
# password = "globalShouldScrubThis"`
	entry.TenantOverrides = &config.OPATenantDecisionLog{
		ScrubPolicyCredentials: false, // per-tenant off (no effect — cannot loosen global)
	}
	dl.write(entry)

	if strings.Contains(buf.String(), "globalShouldScrubThis") {
		t.Error("global scrub should apply even when per-tenant flag is false")
	}
}

// --- no cross-tenant leak ---

func TestDecisionLog_TenantOverrideNoLeakBetweenTenants(t *testing.T) {
	dl, buf := newBufDecisionLog(config.OPADecisionLogConfig{
		Enabled:      true,
		IncludeInput: true,
	})

	// Tenant A: redacts email.
	entryA := baseEntry()
	entryA.TenantID = "tenant_a"
	entryA.TenantOverrides = &config.OPATenantDecisionLog{
		AdditionalRedactFields: []string{"user.claims.email"},
	}
	dl.write(entryA)

	// Tenant B: no overrides — email must appear unredacted.
	entryB := baseEntry()
	entryB.TenantID = "tenant_b"
	dl.write(entryB)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 log lines, got %d", len(lines))
	}

	type inputDoc struct {
		Input map[string]any `json:"input"`
	}
	var recA, recB inputDoc
	_ = json.Unmarshal([]byte(lines[0]), &recA)
	_ = json.Unmarshal([]byte(lines[1]), &recB)

	claimsA := recA.Input["user"].(map[string]any)["claims"].(map[string]any)
	if claimsA["email"] != "[REDACTED]" {
		t.Errorf("tenant A email should be redacted, got %v", claimsA["email"])
	}

	claimsB := recB.Input["user"].(map[string]any)["claims"].(map[string]any)
	if claimsB["email"] == "[REDACTED]" {
		t.Error("tenant B email must not be redacted — tenant A overrides must not leak")
	}
}

// --- per-tenant retention ---

func TestPruneDecisionLog_TenantRetentionTighterThanGlobal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.ndjson")

	// Global: 10 days. Tenant "strict": 2 days.
	budgets := map[string]config.OPATenantBudget{
		"strict": {
			DecisionLog: &config.OPATenantDecisionLog{RetentionDays: 2},
		},
	}

	f, _ := os.Create(path)
	enc := json.NewEncoder(f)
	// "strict" entry 5 days old — within global 10d but outside per-tenant 2d → prune.
	_ = enc.Encode(DecisionEntry{Timestamp: time.Now().UTC().AddDate(0, 0, -5), TenantID: "strict", Decision: "grant"})
	// "other" entry 5 days old — within global 10d → keep.
	_ = enc.Encode(DecisionEntry{Timestamp: time.Now().UTC().AddDate(0, 0, -5), TenantID: "other", Decision: "deny"})
	f.Close()

	if err := pruneDecisionLog(path, 10, budgets); err != nil {
		t.Fatalf("pruneDecisionLog: %v", err)
	}

	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), `"strict"`) {
		t.Error("strict-tenant entry (5d old, 2d retention) should have been pruned")
	}
	if !strings.Contains(string(data), `"other"`) {
		t.Error("other-tenant entry (5d old, 10d global retention) should have been kept")
	}
}

func TestPruneDecisionLog_TenantRetentionWhenGlobalIsUnlimited(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.ndjson")

	// Global: 0 (unlimited). Tenant "finite": 3 days.
	budgets := map[string]config.OPATenantBudget{
		"finite": {
			DecisionLog: &config.OPATenantDecisionLog{RetentionDays: 3},
		},
	}

	f, _ := os.Create(path)
	enc := json.NewEncoder(f)
	// "finite" entry 10 days old — no global limit, but per-tenant 3d → prune.
	_ = enc.Encode(DecisionEntry{Timestamp: time.Now().UTC().AddDate(0, 0, -10), TenantID: "finite", Decision: "grant"})
	// No-tenant entry 10 days old — global is unlimited → keep.
	_ = enc.Encode(DecisionEntry{Timestamp: time.Now().UTC().AddDate(0, 0, -10), TenantID: "", Decision: "deny"})
	f.Close()

	if err := pruneDecisionLog(path, 0, budgets); err != nil {
		t.Fatalf("pruneDecisionLog: %v", err)
	}

	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), `"finite"`) {
		t.Error("finite-tenant entry should have been pruned by per-tenant retention")
	}
	if !strings.Contains(string(data), "deny") {
		t.Error("no-tenant entry should be kept when global retention is unlimited")
	}
}

func TestPruneDecisionLog_NoRetentionConfigured_IsNoop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.ndjson")

	f, _ := os.Create(path)
	enc := json.NewEncoder(f)
	_ = enc.Encode(DecisionEntry{Timestamp: time.Now().UTC().AddDate(0, 0, -100), Decision: "grant"})
	f.Close()

	sizeBefore, _ := os.Stat(path)
	if err := pruneDecisionLog(path, 0, nil); err != nil {
		t.Fatalf("pruneDecisionLog: %v", err)
	}
	sizeAfter, _ := os.Stat(path)

	// File must not be touched — fast path returns before opening.
	if sizeBefore.ModTime() != sizeAfter.ModTime() {
		t.Error("file was modified despite no retention configured anywhere")
	}
}
