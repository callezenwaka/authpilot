package oidc

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"authpilot/server/internal/domain"
	"authpilot/server/internal/store/memory"
)

func newHeaderPropDeps(headerPropagation bool) RouterDeps {
	users := memory.NewUserStore()
	km, _ := NewKeyManager()
	issuer := NewIssuer(km, DefaultTokenConfig(), "http://localhost:8026")
	return RouterDeps{
		Flows:             memory.NewFlowStore(),
		Users:             users,
		Sessions:          memory.NewSessionStore(),
		KeyMgr:            km,
		Issuer:            issuer,
		IssuerURL:         "http://localhost:8026",
		HeaderPropagation: headerPropagation,
	}
}

func seedHeaderPropUser(dep RouterDeps) (domain.User, string) {
	u := domain.User{
		ID:          "usr_hp_test",
		Email:       "hp@example.com",
		DisplayName: "HP User",
		Groups:      []string{"admins", "devs"},
	}
	created, err := dep.Users.Create(u)
	if err != nil {
		panic("seed header prop user: " + err.Error())
	}

	// Use the dep's issuer to sign (so the dep's KeyManager can verify).
	token, _ := dep.Issuer.MintForUser(created, "test-client", nil, 0)
	return created, token.AccessToken
}

func TestHeaderPropagation_Enabled(t *testing.T) {
	dep := newHeaderPropDeps(true)
	user, token := seedHeaderPropUser(dep)

	router := NewRouter(dep)
	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-User-ID") != user.ID {
		t.Errorf("X-User-ID: want %q, got %q", user.ID, rec.Header().Get("X-User-ID"))
	}
	if rec.Header().Get("X-User-Email") != user.Email {
		t.Errorf("X-User-Email: want %q, got %q", user.Email, rec.Header().Get("X-User-Email"))
	}
	// Groups joined with comma.
	if rec.Header().Get("X-User-Groups") != "admins,devs" {
		t.Errorf("X-User-Groups: want %q, got %q", "admins,devs", rec.Header().Get("X-User-Groups"))
	}
}

func TestHeaderPropagation_Disabled(t *testing.T) {
	dep := newHeaderPropDeps(false)
	_, token := seedHeaderPropUser(dep)

	router := NewRouter(dep)
	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	for _, h := range []string{"X-User-ID", "X-User-Email", "X-User-Groups"} {
		if rec.Header().Get(h) != "" {
			t.Errorf("%s should be absent when header propagation is disabled, got %q", h, rec.Header().Get(h))
		}
	}
}

func TestHeaderPropagation_NoGroups(t *testing.T) {
	dep := newHeaderPropDeps(true)
	u := domain.User{
		ID:    "usr_nogroup",
		Email: "nogroup@example.com",
	}
	if _, err := dep.Users.Create(u); err != nil {
		t.Fatalf("create user: %v", err)
	}
	token, _ := dep.Issuer.MintForUser(u, "c", nil, 0)

	router := NewRouter(dep)
	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	// X-User-Groups present but empty when user has no groups.
	if rec.Header().Get("X-User-Groups") != "" {
		t.Errorf("X-User-Groups: want empty string for user with no groups, got %q", rec.Header().Get("X-User-Groups"))
	}
}
