package sqlite

import (
	"path/filepath"
	"testing"
	"time"

	"furnace/server/internal/domain"
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
