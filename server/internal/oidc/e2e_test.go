package oidc_test

// End-to-end integration test using golang.org/x/oauth2 as the real OIDC
// client library. This exercises the full authorize → token → userinfo path
// through a live httptest.Server, verifying that Authpilot is interoperable
// with a standard OAuth 2.0 / OIDC client — not just with hand-rolled HTTP
// requests.
//
// The test spins up:
//   - An httptest.Server running the Authpilot OIDC router (protocol server)
//   - A second httptest.Server acting as the relying-party callback endpoint
//
// Flow:
//  1. oauth2.Config.AuthCodeURL builds the authorization URL (PKCE S256)
//  2. http.Get follows the redirect to /login (simulates the browser)
//  3. The login page returns a flow_id; we manually advance the flow to
//     "complete" via the management store (simulating a user approving login)
//  4. GET /authorize/complete issues the auth code and redirects to our callback
//  5. oauth2.Config.Exchange redeems the code for a TokenSet
//  6. oauth2.TokenSource.Token refreshes using the stored refresh_token
//  7. GET /userinfo with the access token returns the expected claims

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"authpilot/server/internal/domain"
	"authpilot/server/internal/oidc"
	"authpilot/server/internal/store/memory"
)

func TestE2E_OIDCClientLibrary(t *testing.T) {
	// ── Setup stores and issuer ──────────────────────────────────────────────
	flows := memory.NewFlowStore()
	users := memory.NewUserStore()
	sessions := memory.NewSessionStore()

	km, err := oidc.NewKeyManager()
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}

	// Use a short refresh TTL so we can verify rotation without waiting.
	tokenCfg := oidc.TokenConfig{
		AccessTokenTTL:  1 * time.Hour,
		IDTokenTTL:      1 * time.Hour,
		RefreshTokenTTL: 24 * time.Hour,
	}

	// Seed a user.
	user := domain.User{
		ID:          "usr_e2e_lib",
		Email:       "carol@example.com",
		DisplayName: "Carol",
		Groups:      []string{"staff"},
	}
	if _, err := users.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	// ── OIDC server ──────────────────────────────────────────────────────────
	// We need to know the server URL before building the issuer, so we use
	// NewUnstartedServer and set the URL after Start.
	oidcSrv := httptest.NewUnstartedServer(nil)
	oidcSrv.Start()
	t.Cleanup(oidcSrv.Close)

	issuerURL := oidcSrv.URL
	issuer := oidc.NewIssuer(km, tokenCfg, issuerURL)

	// Callback server — captures the code redirect.
	var capturedCode, capturedState string
	callbackSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedCode = r.URL.Query().Get("code")
		capturedState = r.URL.Query().Get("state")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(callbackSrv.Close)

	redirectURI := callbackSrv.URL + "/callback"

	dep := oidc.RouterDeps{
		Flows:     flows,
		Users:     users,
		Sessions:  sessions,
		KeyMgr:    km,
		Issuer:    issuer,
		IssuerURL: issuerURL,
		LoginURL:  "http://unused/login", // not followed in this test
	}
	oidcSrv.Config.Handler = oidc.NewRouter(dep)

	// ── oauth2.Config (the real client library) ──────────────────────────────
	oauthCfg := &oauth2.Config{
		ClientID:    "e2e-client",
		RedirectURL: redirectURI,
		Scopes:      []string{"openid", "email", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  issuerURL + "/authorize",
			TokenURL: issuerURL + "/oauth2/token",
		},
	}

	// ── Step 1: build auth URL with PKCE via oauth2 library ──────────────────
	verifier := oauth2.GenerateVerifier()
	authURL := oauthCfg.AuthCodeURL(
		"state-xyz",
		oauth2.S256ChallengeOption(verifier),
	)

	// ── Step 2: follow the authorize redirect (stop at login redirect) ───────
	noFollowClient := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := noFollowClient.Get(authURL)
	if err != nil {
		t.Fatalf("GET authorize: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 from /authorize, got %d", resp.StatusCode)
	}
	loginRedirect := resp.Header.Get("Location")
	if !strings.Contains(loginRedirect, "flow_id=") {
		t.Fatalf("expected flow_id in login redirect, got %q", loginRedirect)
	}

	// Extract the flow_id.
	loginURL, _ := url.Parse(loginRedirect)
	flowID := loginURL.Query().Get("flow_id")
	if flowID == "" {
		t.Fatal("flow_id missing from login redirect")
	}

	// ── Step 3: advance flow to complete (simulate user login) ───────────────
	flow, err := flows.GetByID(flowID)
	if err != nil {
		t.Fatalf("get flow: %v", err)
	}
	flow.State = "complete"
	flow.UserID = user.ID
	if _, err := flows.Update(flow); err != nil {
		t.Fatalf("update flow: %v", err)
	}

	// ── Step 4: GET /authorize/complete → redirect to callback ───────────────
	resp2, err := noFollowClient.Get(issuerURL + "/authorize/complete?flow_id=" + flowID)
	if err != nil {
		t.Fatalf("GET authorize/complete: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 from /authorize/complete, got %d", resp2.StatusCode)
	}
	cbLoc := resp2.Header.Get("Location")

	// Follow the redirect to the callback server to capture code+state.
	resp3, err := http.Get(cbLoc)
	if err != nil {
		t.Fatalf("GET callback: %v", err)
	}
	resp3.Body.Close()

	if capturedCode == "" {
		t.Fatal("callback did not receive a code")
	}
	if capturedState != "state-xyz" {
		t.Errorf("state mismatch: got %q", capturedState)
	}

	// ── Step 5: exchange code for tokens using oauth2 library ────────────────
	ctx := context.Background()
	tokenResp, err := oauthCfg.Exchange(ctx, capturedCode, oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatalf("oauth2 Exchange: %v", err)
	}
	if tokenResp.AccessToken == "" {
		t.Error("access_token should not be empty")
	}
	if tokenResp.RefreshToken == "" {
		t.Error("refresh_token should not be empty after code exchange")
	}

	// ── Step 6: call /userinfo with the access token ──────────────────────────
	req, _ := http.NewRequest(http.MethodGet, issuerURL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	resp4, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET userinfo: %v", err)
	}
	defer resp4.Body.Close()
	if resp4.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /userinfo, got %d", resp4.StatusCode)
	}
	var claims map[string]any
	if err := json.NewDecoder(resp4.Body).Decode(&claims); err != nil {
		t.Fatalf("decode userinfo: %v", err)
	}
	if claims["email"] != "carol@example.com" {
		t.Errorf("userinfo email: want carol@example.com, got %v", claims["email"])
	}
	if claims["sub"] != "usr_e2e_lib" {
		t.Errorf("userinfo sub: want usr_e2e_lib, got %v", claims["sub"])
	}

	// ── Step 7: refresh using the stored refresh token ────────────────────────
	// Use an already-expired token so the library is forced to call /token
	// with grant_type=refresh_token immediately.
	expiredToken := &oauth2.Token{
		AccessToken:  tokenResp.AccessToken,
		TokenType:    "Bearer",
		RefreshToken: tokenResp.RefreshToken,
		Expiry:       time.Now().Add(-1 * time.Second),
	}
	ts := oauthCfg.TokenSource(ctx, expiredToken)
	newToken, err := ts.Token()
	if err != nil {
		t.Fatalf("TokenSource.Token (refresh): %v", err)
	}
	if newToken.AccessToken == "" {
		t.Error("refreshed access_token should not be empty")
	}
	if newToken.RefreshToken == "" {
		t.Error("rotated refresh_token should not be empty")
	}
	if newToken.RefreshToken == tokenResp.RefreshToken {
		t.Error("refresh_token should be rotated after use")
	}

	// ── Step 8: old refresh token must be rejected ────────────────────────────
	staleForm := url.Values{}
	staleForm.Set("grant_type", "refresh_token")
	staleForm.Set("refresh_token", tokenResp.RefreshToken)
	resp5, err := http.PostForm(issuerURL+"/oauth2/token", staleForm)
	if err != nil {
		t.Fatalf("POST token (stale refresh): %v", err)
	}
	defer resp5.Body.Close()
	if resp5.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for stale refresh token, got %d", resp5.StatusCode)
	}
	var errBody map[string]string
	_ = json.NewDecoder(resp5.Body).Decode(&errBody)
	if errBody["error"] != "invalid_grant" {
		t.Errorf("expected invalid_grant, got %q", errBody["error"])
	}

	t.Logf("E2E OIDC flow complete: code=%s… at=%s… rt=%s…",
		capturedCode[:8], newToken.AccessToken[:12], newToken.RefreshToken[:8])
}

// TestE2E_Discovery verifies the discovery document returned to the oauth2
// library contains all fields required for a client to bootstrap.
func TestE2E_Discovery(t *testing.T) {
	dep := newTestDeps(t)
	srv := httptest.NewServer(oidc.NewRouter(dep))
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}

	required := []string{
		"issuer",
		"authorization_endpoint",
		"token_endpoint",
		"userinfo_endpoint",
		"jwks_uri",
		"response_types_supported",
		"subject_types_supported",
		"id_token_signing_alg_values_supported",
		"scopes_supported",
		"grant_types_supported",
		"code_challenge_methods_supported",
	}
	for _, field := range required {
		if doc[field] == nil {
			t.Errorf("discovery missing required field %q", field)
		}
	}

	// Verify grant_types_supported includes refresh_token.
	grantTypes, _ := doc["grant_types_supported"].([]any)
	found := false
	for _, gt := range grantTypes {
		if fmt.Sprint(gt) == "refresh_token" {
			found = true
		}
	}
	if !found {
		t.Error("discovery grant_types_supported should include refresh_token")
	}
}
