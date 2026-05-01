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

// --- helpers ---

func newTestDecisionLog(t *testing.T, cfg config.OPADecisionLogConfig) *decisionLog {
	t.Helper()
	dl, err := newDecisionLog(cfg)
	if err != nil {
		t.Fatalf("newDecisionLog: %v", err)
	}
	t.Cleanup(func() { _ = dl.Close() })
	return dl
}

func baseEntry() DecisionEntry {
	return DecisionEntry{
		Timestamp:     time.Now().UTC(),
		UserID:        "usr_1",
		Action:        "read",
		Resource:      "doc",
		Allow:         true,
		Decision:      "grant",
		PolicyVersion: "inline",
		Input: map[string]any{
			"user": map[string]any{
				"claims": map[string]any{
					"email":    "alice@example.com",
					"password": "hunter2",
					"sub":      "usr_1",
				},
			},
			"action": "read",
		},
		Policy: `package authz
default allow := false
allow if { input.user.claims.sub == "usr_1" }`,
	}
}

// --- redactPath unit tests ---

func TestRedactPath_LeafRedacted(t *testing.T) {
	m := map[string]any{"a": map[string]any{"b": "secret"}}
	redactPath(m, "a.b")
	got := m["a"].(map[string]any)["b"]
	if got != "[REDACTED]" {
		t.Errorf("got %q, want [REDACTED]", got)
	}
}

func TestRedactPath_MissingKeyIgnored(t *testing.T) {
	m := map[string]any{"a": "keep"}
	redactPath(m, "b.c")
	if m["a"] != "keep" {
		t.Error("unrelated key mutated")
	}
}

func TestRedactPath_ShallowKey(t *testing.T) {
	m := map[string]any{"token": "abc123"}
	redactPath(m, "token")
	if m["token"] != "[REDACTED]" {
		t.Errorf("got %q", m["token"])
	}
}

func TestRedactPath_NonMapIntermediateIgnored(t *testing.T) {
	// "user" is a string, not a map — path should be silently skipped.
	m := map[string]any{"user": "string_value"}
	redactPath(m, "user.email") // should not panic
	if m["user"] != "string_value" {
		t.Error("intermediate non-map value mutated")
	}
}

// --- deepCloneMap ---

func TestDeepCloneMap_DoesNotMutateOriginal(t *testing.T) {
	orig := map[string]any{
		"user": map[string]any{"email": "alice@example.com"},
	}
	clone := deepCloneMap(orig)
	redactPath(clone, "user.email")

	// Original should be unmodified.
	if orig["user"].(map[string]any)["email"] != "alice@example.com" {
		t.Error("deepCloneMap did not isolate original from redaction")
	}
}

// --- redact_fields integration ---

func TestDecisionLog_RedactFields_InputScrubbed(t *testing.T) {
	var buf strings.Builder
	dl := &decisionLog{
		cfg: config.OPADecisionLogConfig{
			Enabled:      true,
			IncludeInput: true,
			RedactFields: []string{"user.claims.password", "user.claims.email"},
		},
	}
	dl.w = writerFunc(func(p []byte) (int, error) { buf.Write(p); return len(p), nil })
	dl.enc = json.NewEncoder(dl.w)

	dl.write(baseEntry())

	body := buf.String()
	if strings.Contains(body, "hunter2") {
		t.Error("password leaked into decision log")
	}
	if strings.Contains(body, "alice@example.com") {
		t.Error("email leaked into decision log")
	}
	if !strings.Contains(body, "[REDACTED]") {
		t.Error("expected [REDACTED] marker in output")
	}
	// Unredacted field must survive.
	if !strings.Contains(body, "usr_1") {
		t.Error("sub was incorrectly redacted")
	}
}

func TestDecisionLog_RedactFields_OriginalInputUnmodified(t *testing.T) {
	entry := baseEntry()
	origEmail := entry.Input["user"].(map[string]any)["claims"].(map[string]any)["email"]

	var buf strings.Builder
	dl := &decisionLog{
		cfg: config.OPADecisionLogConfig{
			Enabled:      true,
			IncludeInput: true,
			RedactFields: []string{"user.claims.email"},
		},
	}
	dl.w = writerFunc(func(p []byte) (int, error) { buf.Write(p); return len(p), nil })
	dl.enc = json.NewEncoder(dl.w)

	dl.write(entry)

	// Caller's map must not have been modified.
	afterEmail := entry.Input["user"].(map[string]any)["claims"].(map[string]any)["email"]
	if afterEmail != origEmail {
		t.Errorf("write() mutated caller's Input: got %v", afterEmail)
	}
}

func TestDecisionLog_NoRedactFields_InputPassedThrough(t *testing.T) {
	var buf strings.Builder
	dl := &decisionLog{
		cfg: config.OPADecisionLogConfig{
			Enabled:      true,
			IncludeInput: true,
		},
	}
	dl.w = writerFunc(func(p []byte) (int, error) { buf.Write(p); return len(p), nil })
	dl.enc = json.NewEncoder(dl.w)

	dl.write(baseEntry())

	if !strings.Contains(buf.String(), "alice@example.com") {
		t.Error("email should appear when no redact_fields configured")
	}
}

// --- scrub_policy_credentials ---

func TestScrubCredentials_BearerToken(t *testing.T) {
	policy := `package authz
# Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c3JfMSJ9.sig
default allow := false`
	out := scrubCredentials(policy)
	if strings.Contains(out, "eyJhbGciOiJSUzI1NiJ9") {
		t.Error("bearer token not scrubbed")
	}
}

func TestScrubCredentials_PasswordAssignment(t *testing.T) {
	policy := `package authz
# password = "hunter2secret"`
	out := scrubCredentials(policy)
	if strings.Contains(out, "hunter2secret") {
		t.Error("password value not scrubbed")
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Error("expected REDACTED marker")
	}
}

func TestScrubCredentials_PreservesNormalCode(t *testing.T) {
	policy := `package authz
default allow := false
allow if { input.user.role == "admin" }`
	out := scrubCredentials(policy)
	if !strings.Contains(out, `input.user.role == "admin"`) {
		t.Errorf("normal policy code was altered: %s", out)
	}
}

func TestDecisionLog_ScrubCredentials_Applied(t *testing.T) {
	var buf strings.Builder
	dl := &decisionLog{
		cfg: config.OPADecisionLogConfig{
			Enabled:                true,
			IncludePolicy:          true,
			ScrubPolicyCredentials: true,
		},
	}
	dl.w = writerFunc(func(p []byte) (int, error) { buf.Write(p); return len(p), nil })
	dl.enc = json.NewEncoder(dl.w)

	entry := baseEntry()
	entry.Policy = `package authz
# secret = "topsecret123"
default allow := false`
	dl.write(entry)

	if strings.Contains(buf.String(), "topsecret123") {
		t.Error("credential leaked into decision log despite ScrubPolicyCredentials=true")
	}
}

// --- retention ---

func TestPruneDecisionLog_RemovesOldEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.ndjson")

	// Write 3 entries: two old, one recent.
	old1 := DecisionEntry{Timestamp: time.Now().UTC().AddDate(0, 0, -10), Decision: "grant"}
	old2 := DecisionEntry{Timestamp: time.Now().UTC().AddDate(0, 0, -5), Decision: "deny"}
	recent := DecisionEntry{Timestamp: time.Now().UTC(), Decision: "grant"}

	f, _ := os.Create(path)
	enc := json.NewEncoder(f)
	_ = enc.Encode(old1)
	_ = enc.Encode(old2)
	_ = enc.Encode(recent)
	f.Close()

	if err := pruneDecisionLog(path, 3); err != nil {
		t.Fatalf("pruneDecisionLog: %v", err)
	}

	data, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 line after pruning, got %d:\n%s", len(lines), string(data))
	}
	var got DecisionEntry
	_ = json.Unmarshal([]byte(lines[0]), &got)
	if got.Decision != "grant" {
		t.Errorf("wrong entry kept: %q", got.Decision)
	}
}

func TestPruneDecisionLog_NonexistentFileIsNoop(t *testing.T) {
	err := pruneDecisionLog(filepath.Join(t.TempDir(), "missing.ndjson"), 7)
	if err != nil {
		t.Errorf("expected no error for missing file, got: %v", err)
	}
}

func TestPruneDecisionLog_KeepsUnparseable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.ndjson")
	// Write one valid old entry and one malformed line.
	f, _ := os.Create(path)
	enc := json.NewEncoder(f)
	_ = enc.Encode(DecisionEntry{Timestamp: time.Now().UTC().AddDate(0, 0, -10), Decision: "deny"})
	f.WriteString("not-json\n") //nolint:errcheck
	f.Close()

	if err := pruneDecisionLog(path, 3); err != nil {
		t.Fatalf("pruneDecisionLog: %v", err)
	}

	data, _ := os.ReadFile(path)
	// Old parseable entry dropped; malformed line kept.
	if !strings.Contains(string(data), "not-json") {
		t.Error("unparseable line should be preserved conservatively")
	}
	if strings.Contains(string(data), "deny") {
		t.Error("old entry should have been pruned")
	}
}

func TestDecisionLog_FileDestinationRetention(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "test.ndjson")

	// Pre-populate with one old entry.
	f, _ := os.Create(logPath)
	enc := json.NewEncoder(f)
	_ = enc.Encode(DecisionEntry{
		Timestamp: time.Now().UTC().AddDate(0, 0, -30),
		Decision:  "old_grant",
	})
	f.Close()

	dl := newTestDecisionLog(t, config.OPADecisionLogConfig{
		Enabled:       true,
		Destination:   logPath,
		RetentionDays: 7,
	})

	// Write a fresh entry.
	entry := baseEntry()
	entry.Decision = "new_grant"
	dl.write(entry)

	data, _ := os.ReadFile(logPath)
	if strings.Contains(string(data), "old_grant") {
		t.Error("old entry should have been pruned by retention on open")
	}
	if !strings.Contains(string(data), "new_grant") {
		t.Error("new entry should be present")
	}
}
