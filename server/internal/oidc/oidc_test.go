package oidc_test

import (
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"

	"furnace/server/internal/domain"
	"furnace/server/internal/oidc"
	"furnace/server/internal/store/memory"
)

// ---------------------------------------------------------------------------
// KeyManager
// ---------------------------------------------------------------------------

func TestKeyManager_JWKS(t *testing.T) {
	km, err := oidc.NewKeyManager()
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	jwks := km.JWKS()
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(jwks.Keys))
	}
	k := jwks.Keys[0]
	if k.Algorithm != "RS256" {
		t.Errorf("expected RS256, got %s", k.Algorithm)
	}
	if k.Use != "sig" {
		t.Errorf("expected use=sig, got %s", k.Use)
	}
	if k.KeyID == "" {
		t.Error("key id should not be empty")
	}
}

func TestKeyManager_Signer(t *testing.T) {
	km, err := oidc.NewKeyManager()
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	signer, err := km.Signer()
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	if signer == nil {
		t.Fatal("expected non-nil signer")
	}
}

func TestKeyManager_KeyStrengthAtLeast3072(t *testing.T) {
	km, err := oidc.NewKeyManager()
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	jwks := km.JWKS()
	if len(jwks.Keys) == 0 {
		t.Fatal("no keys in JWKS")
	}
	pub, ok := jwks.Keys[0].Key.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", jwks.Keys[0].Key)
	}
	if bits := pub.N.BitLen(); bits < 3072 {
		t.Errorf("RSA key must be at least 3072 bits; got %d", bits)
	}
}

// TestKeyManager_RotateOverlap exercises the JWKS overlap window: after a
// rotation, both the new active key and the previously-active key remain
// published, and tokens signed before the rotation still verify.
func TestKeyManager_RotateOverlap(t *testing.T) {
	km, err := oidc.NewKeyManager()
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}

	// Sign a token under the original key.
	signer, err := km.Signer()
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	originalKID := km.JWKS().Keys[0].KeyID
	oldToken, err := jwt.Signed(signer).Claims(jwt.Claims{
		Subject: "alice",
		Expiry:  jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
	}).Serialize()
	if err != nil {
		t.Fatalf("serialize old token: %v", err)
	}

	// Rotate.
	if err := km.Rotate(); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	jwks := km.JWKS()
	if len(jwks.Keys) != 2 {
		t.Fatalf("expected 2 keys in JWKS after one rotation, got %d", len(jwks.Keys))
	}
	if jwks.Keys[0].KeyID == originalKID {
		t.Error("newest key should be at index 0; got the original kid")
	}
	if jwks.Keys[1].KeyID != originalKID {
		t.Errorf("expected previously-active kid at index 1; got %s, want %s",
			jwks.Keys[1].KeyID, originalKID)
	}

	// Old token must still verify against the retired key.
	if _, active, err := km.VerifyJWT(oldToken); err != nil {
		t.Fatalf("verify old token: %v", err)
	} else if !active {
		t.Error("token signed before rotation must still verify inside the overlap window")
	}

	// New tokens are signed under the new active key.
	newSigner, err := km.Signer()
	if err != nil {
		t.Fatalf("Signer after rotate: %v", err)
	}
	newToken, err := jwt.Signed(newSigner).Claims(jwt.Claims{
		Subject: "bob",
		Expiry:  jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
	}).Serialize()
	if err != nil {
		t.Fatalf("serialize new token: %v", err)
	}
	if _, active, err := km.VerifyJWT(newToken); err != nil {
		t.Fatalf("verify new token: %v", err)
	} else if !active {
		t.Error("token signed under new active key failed verification")
	}
}

// ---------------------------------------------------------------------------
// PKCE
// ---------------------------------------------------------------------------

func TestVerifyPKCE_S256(t *testing.T) {
	// Known pair from RFC 7636 Appendix B.
	knownVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	knownChallenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	if err := oidc.VerifyPKCE(knownChallenge, "S256", knownVerifier); err != nil {
		t.Errorf("S256 verify failed: %v", err)
	}
}

func TestVerifyPKCE_PlainRejected(t *testing.T) {
	if err := oidc.VerifyPKCE("mysecret", "plain", "mysecret"); err == nil {
		t.Error("expected plain method to be rejected")
	}
}

func TestVerifyPKCE_WrongVerifier(t *testing.T) {
	knownChallenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if err := oidc.VerifyPKCE(knownChallenge, "S256", "wrongverifier"); err == nil {
		t.Error("expected error for wrong verifier")
	}
}

func TestVerifyPKCE_MissingChallenge(t *testing.T) {
	if err := oidc.VerifyPKCE("", "S256", "anything"); err == nil {
		t.Error("expected error for empty challenge")
	}
}

func TestVerifyPKCE_MissingVerifier(t *testing.T) {
	if err := oidc.VerifyPKCE("somechallenge", "S256", ""); err == nil {
		t.Error("expected error for empty verifier")
	}
}

// ---------------------------------------------------------------------------
// Token Issuer
// ---------------------------------------------------------------------------

func newTestIssuer(t *testing.T) *oidc.Issuer {
	t.Helper()
	km, err := oidc.NewKeyManager()
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	return oidc.NewIssuer(km, oidc.DefaultTokenConfig(), "http://localhost:8026")
}

func TestIssuer_Issue(t *testing.T) {
	issuer := newTestIssuer(t)

	flow := domain.Flow{
		ID:       "flow_1",
		ClientID: "test-client",
		Scopes:   []string{"openid", "email"},
		Nonce:    "testnonce",
	}
	user := domain.User{
		ID:          "usr_1",
		Email:       "alice@example.com",
		DisplayName: "Alice",
		Groups:      []string{"eng"},
	}

	tokens, err := issuer.Issue(flow, user)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if tokens.AccessToken == "" {
		t.Error("access_token should not be empty")
	}
	if tokens.IDToken == "" {
		t.Error("id_token should not be empty")
	}
	if tokens.TokenType != "Bearer" {
		t.Errorf("expected Bearer, got %s", tokens.TokenType)
	}
	if tokens.ExpiresIn != 3600 {
		t.Errorf("expected 3600, got %d", tokens.ExpiresIn)
	}
	if tokens.Scope != "openid email" {
		t.Errorf("expected 'openid email', got %q", tokens.Scope)
	}
}

// ---------------------------------------------------------------------------
// OIDC HTTP handlers (integration-style)
// ---------------------------------------------------------------------------

func newTestDeps(t *testing.T) oidc.RouterDeps {
	t.Helper()
	km, err := oidc.NewKeyManager()
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	issuer := oidc.NewIssuer(km, oidc.DefaultTokenConfig(), "http://localhost:8026")
	return oidc.RouterDeps{
		Flows:     memory.NewFlowStore(),
		Users:     memory.NewUserStore(),
		Sessions:  memory.NewSessionStore(),
		KeyMgr:    km,
		Issuer:    issuer,
		IssuerURL: "http://localhost:8026",
		LoginURL:  "http://localhost:8025/login",
	}
}

func TestDiscovery(t *testing.T) {
	dep := newTestDeps(t)
	srv := httptest.NewServer(oidc.NewRouter(dep))
	defer srv.Close()

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
	for _, field := range []string{"issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"} {
		if doc[field] == nil {
			t.Errorf("discovery missing field %q", field)
		}
	}
}

func TestJWKS(t *testing.T) {
	dep := newTestDeps(t)
	srv := httptest.NewServer(oidc.NewRouter(dep))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("GET jwks: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var jwks map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	keys, _ := jwks["keys"].([]any)
	if len(keys) != 1 {
		t.Errorf("expected 1 key, got %d", len(keys))
	}
}

func TestAuthorize_MissingClientID(t *testing.T) {
	dep := newTestDeps(t)
	srv := httptest.NewServer(oidc.NewRouter(dep))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/authorize?response_type=code&redirect_uri=http://app/cb&code_challenge=abc")
	if err != nil {
		t.Fatalf("GET authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAuthorize_MissingPKCE(t *testing.T) {
	dep := newTestDeps(t)
	srv := httptest.NewServer(oidc.NewRouter(dep))
	defer srv.Close()

	// No code_challenge → should redirect to redirect_uri with error
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(srv.URL + "/authorize?client_id=app&response_type=code&redirect_uri=http://app/cb&scope=openid")
	if err != nil {
		t.Fatalf("GET authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("expected redirect, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "error=invalid_request") {
		t.Errorf("expected error in redirect, got %q", loc)
	}
}

func TestAuthorize_ValidRedirectsToLogin(t *testing.T) {
	dep := newTestDeps(t)
	srv := httptest.NewServer(oidc.NewRouter(dep))
	defer srv.Close()

	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	q := url.Values{}
	q.Set("client_id", "myapp")
	q.Set("response_type", "code")
	q.Set("redirect_uri", "http://app/callback")
	q.Set("scope", "openid email")
	q.Set("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
	q.Set("code_challenge_method", "S256")
	q.Set("state", "xyz")

	resp, err := client.Get(srv.URL + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("GET authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("expected 302, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "/login") {
		t.Errorf("expected redirect to /login, got %q", loc)
	}
	if !strings.Contains(loc, "flow_id=") {
		t.Errorf("expected flow_id in redirect, got %q", loc)
	}
}

func TestToken_InvalidCode(t *testing.T) {
	dep := newTestDeps(t)
	srv := httptest.NewServer(oidc.NewRouter(dep))
	defer srv.Close()

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "notacode")
	form.Set("redirect_uri", "http://app/callback")
	form.Set("code_verifier", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")

	resp, err := http.PostForm(srv.URL+"/oauth2/token", form)
	if err != nil {
		t.Fatalf("POST token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["error"] != "invalid_grant" {
		t.Errorf("expected invalid_grant, got %q", body["error"])
	}
}

func TestToken_UnsupportedGrantType(t *testing.T) {
	dep := newTestDeps(t)
	srv := httptest.NewServer(oidc.NewRouter(dep))
	defer srv.Close()

	form := url.Values{}
	form.Set("grant_type", "client_credentials")

	resp, err := http.PostForm(srv.URL+"/oauth2/token", form)
	if err != nil {
		t.Fatalf("POST token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestUserinfo_NoToken(t *testing.T) {
	dep := newTestDeps(t)
	srv := httptest.NewServer(oidc.NewRouter(dep))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/userinfo")
	if err != nil {
		t.Fatalf("GET userinfo: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestRevoke_AlwaysOK(t *testing.T) {
	dep := newTestDeps(t)
	srv := httptest.NewServer(oidc.NewRouter(dep))
	defer srv.Close()

	form := url.Values{}
	form.Set("token", "sometoken")

	resp, err := http.PostForm(srv.URL+"/revoke", form)
	if err != nil {
		t.Fatalf("POST revoke: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// End-to-end: authorize → complete → token → userinfo
// ---------------------------------------------------------------------------

func TestFullOIDCFlow(t *testing.T) {
	dep := newTestDeps(t)

	// Seed a user and complete a flow manually.
	user := domain.User{
		ID:          "usr_e2e",
		Email:       "bob@example.com",
		DisplayName: "Bob",
	}
	if _, err := dep.Users.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	now := time.Now().UTC()
	flow := domain.Flow{
		ID:            "flow_e2e",
		State:         "complete",
		Protocol:      "oidc",
		UserID:        "usr_e2e",
		ClientID:      "e2e-client",
		RedirectURI:   "http://app/callback",
		Scopes:        []string{"openid", "email"},
		PKCEChallenge: challenge,
		PKCEMethod:    "S256",
		OAuthState:    "state123",
		CreatedAt:     now,
		ExpiresAt:     now.Add(30 * time.Minute),
	}
	if _, err := dep.Flows.Create(flow); err != nil {
		t.Fatalf("create flow: %v", err)
	}

	srv := httptest.NewServer(oidc.NewRouter(dep))
	defer srv.Close()

	// Step 1: authorize/complete issues the auth code.
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(srv.URL + "/authorize/complete?flow_id=flow_e2e")
	if err != nil {
		t.Fatalf("GET authorize/complete: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 from authorize/complete, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	parsed, _ := url.Parse(loc)
	code := parsed.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect: %q", loc)
	}
	if parsed.Query().Get("state") != "state123" {
		t.Errorf("state mismatch: %q", parsed.Query().Get("state"))
	}

	// Step 2: exchange code for tokens.
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "http://app/callback")
	form.Set("code_verifier", verifier)

	resp2, err := http.PostForm(srv.URL+"/oauth2/token", form)
	if err != nil {
		t.Fatalf("POST token: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from token, got %d", resp2.StatusCode)
	}
	var tokens oidc.TokenSet
	if err := json.NewDecoder(resp2.Body).Decode(&tokens); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if tokens.AccessToken == "" || tokens.IDToken == "" {
		t.Fatal("expected non-empty access_token and id_token")
	}

	// Step 3: call userinfo with the access token.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	resp3, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET userinfo: %v", err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from userinfo, got %d", resp3.StatusCode)
	}
	var info map[string]any
	if err := json.NewDecoder(resp3.Body).Decode(&info); err != nil {
		t.Fatalf("decode userinfo: %v", err)
	}
	if info["email"] != "bob@example.com" {
		t.Errorf("expected email bob@example.com, got %v", info["email"])
	}

	// Step 4: second code redemption must fail (code consumed).
	resp4, err := http.PostForm(srv.URL+"/oauth2/token", form)
	if err != nil {
		t.Fatalf("POST token (replay): %v", err)
	}
	defer resp4.Body.Close()
	if resp4.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 on code replay, got %d", resp4.StatusCode)
	}

	// Step 5: refresh grant returns new tokens and rotates the refresh token.
	refreshForm := url.Values{}
	refreshForm.Set("grant_type", "refresh_token")
	refreshForm.Set("refresh_token", tokens.RefreshToken)

	resp5, err := http.PostForm(srv.URL+"/oauth2/token", refreshForm)
	if err != nil {
		t.Fatalf("POST token (refresh): %v", err)
	}
	defer resp5.Body.Close()
	if resp5.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from refresh grant, got %d", resp5.StatusCode)
	}
	var tokens2 oidc.TokenSet
	if err := json.NewDecoder(resp5.Body).Decode(&tokens2); err != nil {
		t.Fatalf("decode refresh response: %v", err)
	}
	if tokens2.AccessToken == "" {
		t.Error("expected non-empty access_token after refresh")
	}
	if tokens2.RefreshToken == "" {
		t.Error("expected non-empty refresh_token after refresh (rotation)")
	}
	if tokens2.RefreshToken == tokens.RefreshToken {
		t.Error("refresh token should be rotated (old == new)")
	}

	// Step 6: old refresh token must now be rejected.
	resp6, err := http.PostForm(srv.URL+"/oauth2/token", refreshForm)
	if err != nil {
		t.Fatalf("POST token (old refresh token): %v", err)
	}
	defer resp6.Body.Close()
	if resp6.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 on replayed refresh token, got %d", resp6.StatusCode)
	}
}

func TestRefreshGrant_MissingToken(t *testing.T) {
	dep := newTestDeps(t)
	srv := httptest.NewServer(oidc.NewRouter(dep))
	defer srv.Close()

	form := url.Values{}
	form.Set("grant_type", "refresh_token")

	resp, err := http.PostForm(srv.URL+"/oauth2/token", form)
	if err != nil {
		t.Fatalf("POST token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["error"] != "invalid_request" {
		t.Errorf("expected invalid_request, got %q", body["error"])
	}
}

func TestRefreshGrant_UnknownToken(t *testing.T) {
	dep := newTestDeps(t)
	srv := httptest.NewServer(oidc.NewRouter(dep))
	defer srv.Close()

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", "doesnotexist")

	resp, err := http.PostForm(srv.URL+"/oauth2/token", form)
	if err != nil {
		t.Fatalf("POST token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["error"] != "invalid_grant" {
		t.Errorf("expected invalid_grant, got %q", body["error"])
	}
}
