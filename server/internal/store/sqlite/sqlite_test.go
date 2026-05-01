package sqlite

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"furnace/server/internal/domain"
	"furnace/server/internal/store"
)

func TestPersistenceRoundTripFlows(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "furnace.db")

	first, err := New(dbPath)
	if err != nil {
		t.Fatalf("create sqlite store: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	flow := domain.Flow{
		ID:        "flow_persist",
		State:     "initiated",
		Scenario:  "normal",
		Protocol:  "oidc",
		Scopes:    []string{"openid", "profile"},
		CreatedAt: now,
		ExpiresAt: now.Add(30 * time.Minute),
	}
	if _, err := first.Flows().Create(flow); err != nil {
		t.Fatalf("create flow: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close first store: %v", err)
	}

	second, err := New(dbPath)
	if err != nil {
		t.Fatalf("re-open sqlite store: %v", err)
	}
	defer func() { _ = second.Close() }()

	got, err := second.Flows().GetByID("flow_persist")
	if err != nil {
		t.Fatalf("load persisted flow: %v", err)
	}
	if got.State != flow.State {
		t.Fatalf("flow state mismatch: want %q got %q", flow.State, got.State)
	}
	if len(got.Scopes) != 2 || got.Scopes[0] != "openid" {
		t.Fatalf("flow scopes mismatch: %v", got.Scopes)
	}
}

func TestPersistenceRoundTripSessions(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "furnace.db")

	first, err := New(dbPath)
	if err != nil {
		t.Fatalf("create sqlite store: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	sess := domain.Session{
		ID:           "sess_persist",
		UserID:       "usr_1",
		FlowID:       "flow_1",
		Protocol:     "oidc",
		RefreshToken: "tok_secret",
		CreatedAt:    now,
		ExpiresAt:    now.Add(12 * time.Hour),
	}
	if _, err := first.Sessions().Create(sess); err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close first store: %v", err)
	}

	second, err := New(dbPath)
	if err != nil {
		t.Fatalf("re-open sqlite store: %v", err)
	}
	defer func() { _ = second.Close() }()

	got, err := second.Sessions().GetByRefreshToken("tok_secret")
	if err != nil {
		t.Fatalf("load persisted session by refresh token: %v", err)
	}
	if got.UserID != sess.UserID {
		t.Fatalf("session user_id mismatch: want %q got %q", sess.UserID, got.UserID)
	}
}

// ---------------------------------------------------------------------------
// Policy integrity tests
// ---------------------------------------------------------------------------

func newPolicyStore(t *testing.T) (*Store, *PolicyStore) {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "furnace.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, s.Policies()
}

const testPolicy = `package authz
default allow := false
allow if { input.user == "admin" }`

func TestPolicyIntegrity_SignatureSetOnActivate(t *testing.T) {
	_, ps := newPolicyStore(t)

	p := domain.Policy{
		ID: "pol_sig1", Name: "acl", Version: "1.0",
		Content: testPolicy, ContentHash: "sha256ofcontent",
		CreatedAt: time.Now().UTC(),
	}
	if _, err := ps.Create(p); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := ps.Activate("pol_sig1", time.Now().UTC()); err != nil {
		t.Fatalf("Activate: %v", err)
	}

	got, err := ps.GetByID("pol_sig1")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Signature == "" {
		t.Fatal("expected signature to be set after Activate, got empty string")
	}
}

func TestPolicyIntegrity_LoadVerifiesSignature(t *testing.T) {
	_, ps := newPolicyStore(t)

	p := domain.Policy{
		ID: "pol_sig2", Name: "authz", Version: "1.0",
		Content: testPolicy, ContentHash: "abc123",
		CreatedAt: time.Now().UTC(),
	}
	if _, err := ps.Create(p); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := ps.Activate("pol_sig2", time.Now().UTC()); err != nil {
		t.Fatalf("Activate: %v", err)
	}

	// Should load and pass signature verification.
	got, err := ps.GetByName("authz")
	if err != nil {
		t.Fatalf("GetByName: %v", err)
	}
	if got.ID != "pol_sig2" {
		t.Fatalf("wrong policy returned: %q", got.ID)
	}
}

func TestPolicyIntegrity_TamperedContentRejected(t *testing.T) {
	s, ps := newPolicyStore(t)

	p := domain.Policy{
		ID: "pol_tamp", Name: "sensitive", Version: "1.0",
		Content: testPolicy, ContentHash: "originalhash",
		CreatedAt: time.Now().UTC(),
	}
	if _, err := ps.Create(p); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := ps.Activate("pol_tamp", time.Now().UTC()); err != nil {
		t.Fatalf("Activate: %v", err)
	}

	// Simulate DB-level tampering: corrupt the content_hash directly.
	if _, err := s.db.Exec(`UPDATE opa_policies SET content_hash = 'tampered_hash' WHERE id = 'pol_tamp'`); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	_, err := ps.GetByName("sensitive")
	if !errors.Is(err, store.ErrPolicyTampered) {
		t.Fatalf("expected ErrPolicyTampered, got: %v", err)
	}
}

func TestPolicyIntegrity_UnsignedPolicyLoadsOK(t *testing.T) {
	s, ps := newPolicyStore(t)

	// Insert a policy directly with empty signature (simulates pre-signing data).
	_, err := s.db.Exec(`
		INSERT INTO opa_policies (id, name, version, content, content_hash, signature, active, created_at)
		VALUES ('pol_old', 'legacy', '0.1', ?, 'hash0', '', 1, ?)
	`, testPolicy, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		t.Fatalf("direct insert: %v", err)
	}

	// Should load without error (backward compat: no signature = skip verification).
	got, err := ps.GetByName("legacy")
	if err != nil {
		t.Fatalf("GetByName: %v (want backward-compat load)", err)
	}
	if got.ID != "pol_old" {
		t.Fatalf("wrong policy: %q", got.ID)
	}
}

func TestPolicyIntegrity_SigningKeyPersistsAcrossRestarts(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "furnace.db")

	// First open: create policy and activate (generates + persists key).
	s1, err := New(dbPath)
	if err != nil {
		t.Fatalf("New (first): %v", err)
	}
	ps1 := s1.Policies()
	p := domain.Policy{
		ID: "pol_restart", Name: "restart_test", Version: "1.0",
		Content: testPolicy, ContentHash: "hash_restart",
		CreatedAt: time.Now().UTC(),
	}
	if _, err := ps1.Create(p); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := ps1.Activate("pol_restart", time.Now().UTC()); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	_ = s1.Close()

	// Second open: key must be the same, so the stored signature must verify.
	s2, err := New(dbPath)
	if err != nil {
		t.Fatalf("New (second): %v", err)
	}
	defer func() { _ = s2.Close() }()
	ps2 := s2.Policies()

	got, err := ps2.GetByName("restart_test")
	if err != nil {
		t.Fatalf("GetByName after restart: %v", err)
	}
	if got.ID != "pol_restart" {
		t.Fatalf("wrong policy after restart: %q", got.ID)
	}
}

func TestPersistenceRoundTripUsersAndGroups(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "furnace.db")

	first, err := New(dbPath)
	if err != nil {
		t.Fatalf("create sqlite store: %v", err)
	}

	user := domain.User{
		ID:          "usr_1",
		Email:       "persist@example.com",
		DisplayName: "Persisted User",
		Groups:      []string{"engineering"},
		CreatedAt:   time.Now().UTC().Truncate(time.Microsecond),
	}
	if _, err := first.Users().Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	group := domain.Group{
		ID:          "grp_1",
		Name:        "engineering",
		DisplayName: "Engineering",
		MemberIDs:   []string{"usr_1"},
		CreatedAt:   time.Now().UTC().Truncate(time.Microsecond),
	}
	if _, err := first.Groups().Create(group); err != nil {
		t.Fatalf("create group: %v", err)
	}

	if err := first.Close(); err != nil {
		t.Fatalf("close first store: %v", err)
	}

	second, err := New(dbPath)
	if err != nil {
		t.Fatalf("re-open sqlite store: %v", err)
	}
	defer func() { _ = second.Close() }()

	gotUser, err := second.Users().GetByID("usr_1")
	if err != nil {
		t.Fatalf("load persisted user: %v", err)
	}
	if gotUser.Email != user.Email {
		t.Fatalf("user email mismatch, want %q got %q", user.Email, gotUser.Email)
	}

	gotGroup, err := second.Groups().GetByID("grp_1")
	if err != nil {
		t.Fatalf("load persisted group: %v", err)
	}
	if gotGroup.Name != group.Name {
		t.Fatalf("group name mismatch, want %q got %q", group.Name, gotGroup.Name)
	}
}
