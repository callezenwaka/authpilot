package oidc_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"furnace/server/internal/domain"
	flowengine "furnace/server/internal/flow"
	"furnace/server/internal/oidc"
	"furnace/server/internal/store/memory"
)

func newSessionTestDeps(t *testing.T) (oidc.RouterDeps, *memory.FlowStore, *memory.UserStore, *memory.SessionStore) {
	t.Helper()
	km, err := oidc.NewKeyManager()
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	flows := memory.NewFlowStore()
	users := memory.NewUserStore()
	sessions := memory.NewSessionStore()
	issuer := oidc.NewIssuer(km, oidc.DefaultTokenConfig(), "http://localhost:8026")
	dep := oidc.RouterDeps{
		Flows:          flows,
		Users:          users,
		Sessions:       sessions,
		KeyMgr:         km,
		Issuer:         issuer,
		IssuerURL:      "http://localhost:8026",
		LoginURL:       "http://localhost:8025/login",
		SessionHashKey: []byte("test-session-hmac-key-32-bytes!!"),
	}
	return dep, flows, users, sessions
}

// seedReadyFlow creates a completed flow with an auth code, ready for /oauth2/token exchange.
func seedReadyFlow(t *testing.T, flows *memory.FlowStore, users *memory.UserStore) {
	t.Helper()
	user := domain.User{
		ID:          "usr_sess",
		Email:       "sess@example.com",
		DisplayName: "Sess",
	}
	if _, err := users.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	now := time.Now().UTC()
	flow := domain.Flow{
		ID:            "flow_sess",
		State:         string(flowengine.StateComplete),
		UserID:        user.ID,
		Protocol:      "oidc",
		ClientID:      "my-client",
		Scopes:        []string{"openid", "email"},
		RedirectURI:   "http://localhost/callback",
		AuthCode:      "test-code-sess",
		PKCEChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", // S256 of verifier below (RFC 7636 test vector)
		PKCEMethod:    "S256",
		CreatedAt:     now,
		ExpiresAt:     now.Add(30 * time.Minute),
	}
	if _, err := flows.Create(flow); err != nil {
		t.Fatalf("create flow: %v", err)
	}
}

func exchangeAuthCode(t *testing.T, srv *httptest.Server) map[string]any {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "test-code-sess")
	form.Set("redirect_uri", "http://localhost/callback")
	form.Set("client_id", "my-client")
	form.Set("code_verifier", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
	resp, err := http.PostForm(srv.URL+"/oauth2/token", form)
	if err != nil {
		t.Fatalf("POST token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token exchange: expected 200, got %d", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	return body
}

func TestSessionEnrichment_TokenIssued(t *testing.T) {
	dep, flows, users, sessions := newSessionTestDeps(t)
	srv := httptest.NewServer(oidc.NewRouter(dep))
	t.Cleanup(srv.Close)

	seedReadyFlow(t, flows, users)
	exchangeAuthCode(t, srv)

	all, err := sessions.List()
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected 1 session, got %d", len(all))
	}
	sess := all[0]

	if sess.Protocol != "oidc" {
		t.Errorf("Protocol: want oidc, got %q", sess.Protocol)
	}
	if sess.ClientID != "my-client" {
		t.Errorf("ClientID: want my-client, got %q", sess.ClientID)
	}
	if len(sess.Events) == 0 {
		t.Fatal("expected at least one session event")
	}
	if sess.Events[0].Type != "token_issued" {
		t.Errorf("first event type: want token_issued, got %q", sess.Events[0].Type)
	}
}

func TestSessionEnrichment_RefreshAppendsEvent(t *testing.T) {
	dep, flows, users, sessions := newSessionTestDeps(t)
	srv := httptest.NewServer(oidc.NewRouter(dep))
	t.Cleanup(srv.Close)

	seedReadyFlow(t, flows, users)
	tokens := exchangeAuthCode(t, srv)

	refreshToken, _ := tokens["refresh_token"].(string)
	if refreshToken == "" {
		t.Fatal("expected refresh_token in auth code exchange response")
	}

	refreshForm := url.Values{}
	refreshForm.Set("grant_type", "refresh_token")
	refreshForm.Set("refresh_token", refreshToken)
	resp2, err := http.PostForm(srv.URL+"/oauth2/token", refreshForm)
	if err != nil {
		t.Fatalf("POST token (refresh): %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("refresh: expected 200, got %d", resp2.StatusCode)
	}

	all, _ := sessions.List()
	if len(all) != 1 {
		t.Fatalf("expected 1 session, got %d", len(all))
	}
	sess := all[0]
	if len(sess.Events) < 2 {
		t.Fatalf("expected at least 2 events after refresh, got %d: %v", len(sess.Events), sess.Events)
	}
	last := sess.Events[len(sess.Events)-1]
	if last.Type != "refreshed" {
		t.Errorf("last event type: want refreshed, got %q", last.Type)
	}
}

// TestSessionRefreshTokenAtRestIsHashed exercises the H1 #4 invariant: the
// raw refresh token returned to the client never appears in the session
// store. A store dump must reveal only the HMAC-SHA256 hash.
func TestSessionRefreshTokenAtRestIsHashed(t *testing.T) {
	dep, flows, users, sessions := newSessionTestDeps(t)
	srv := httptest.NewServer(oidc.NewRouter(dep))
	t.Cleanup(srv.Close)

	seedReadyFlow(t, flows, users)
	tokens := exchangeAuthCode(t, srv)
	rawRefresh, _ := tokens["refresh_token"].(string)
	if rawRefresh == "" {
		t.Fatal("expected refresh_token in token response")
	}

	all, err := sessions.List()
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected 1 session, got %d", len(all))
	}
	stored := all[0].RefreshToken
	if stored == "" {
		t.Fatal("session has no stored refresh token")
	}
	if stored == rawRefresh {
		t.Fatal("stored refresh token must not equal the raw value returned to the client")
	}
	// Lookup by raw token must succeed (the handler hashes on its way in too).
	if _, err := sessions.GetByRefreshToken(rawRefresh); err == nil {
		t.Fatal("lookup by raw refresh token must NOT match — store contains only the hash")
	}
}
