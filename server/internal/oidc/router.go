package oidc

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"furnace/server/internal/domain"
	flowengine "furnace/server/internal/flow"
	"furnace/server/internal/store"
)

// hashRefreshToken returns the at-rest representation of a refresh token: the
// HMAC-SHA256 of the opaque value, base64url-encoded. The raw token never
// reaches the session store; only the hash does. A store dump reveals nothing
// usable for replay.
func hashRefreshToken(token string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(token))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// HeaderMapping declares one response header to inject on /userinfo responses.
type HeaderMapping struct {
	Name  string // HTTP header name, e.g. "X-User-Email"
	Claim string // userinfo claim key, e.g. "email"
	Join  string // separator when the claim is []any; defaults to ","
}

// RouterDeps groups everything the OIDC router needs.
type RouterDeps struct {
	Flows              store.FlowStore
	Users              store.UserStore
	Sessions           store.SessionStore
	KeyMgr             *KeyManager
	Issuer             *Issuer
	IssuerURL          string          // e.g. "http://localhost:8026"
	LoginURL           string          // e.g. "http://localhost:8025/login"
	HeaderPropagation  bool            // inject X-User-* headers on /userinfo responses
	HeaderMappings     []HeaderMapping // custom mappings; overrides default X-User-* when non-empty
	SessionHashKey     []byte          // HMAC key for at-rest hashing of refresh tokens; required (validated upstream in config)
}

func NewRouter(dep RouterDeps) http.Handler {
	r := mux.NewRouter()

	r.HandleFunc("/.well-known/openid-configuration", discoveryHandler(dep)).Methods(http.MethodGet)
	r.HandleFunc("/.well-known/jwks.json", jwksHandler(dep.KeyMgr)).Methods(http.MethodGet)
	r.HandleFunc("/authorize", authorizeHandler(dep)).Methods(http.MethodGet)
	r.HandleFunc("/authorize/complete", authorizeCompleteHandler(dep)).Methods(http.MethodGet)
	r.HandleFunc("/oauth2/token", tokenHandler(dep)).Methods(http.MethodPost)
	r.HandleFunc("/userinfo", userinfoHandler(dep)).Methods(http.MethodGet, http.MethodPost)
	r.HandleFunc("/revoke", revokeHandler()).Methods(http.MethodPost)
	r.HandleFunc("/oauth2/introspect", introspectHandler(dep)).Methods(http.MethodPost)

	return r
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

func discoveryHandler(dep RouterDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		base := dep.IssuerURL
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer":                                base,
			"authorization_endpoint":                base + "/authorize",
			"token_endpoint":                        base + "/oauth2/token",
			"userinfo_endpoint":                     base + "/userinfo",
			"jwks_uri":                              base + "/.well-known/jwks.json",
			"revocation_endpoint":                   base + "/revoke",
			"introspection_endpoint":                base + "/oauth2/introspect",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic", "none"},
			"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "email", "name", "groups"},
			"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
			"code_challenge_methods_supported":      []string{"S256"},
		})
	}
}

// ---------------------------------------------------------------------------
// JWKS
// ---------------------------------------------------------------------------

func jwksHandler(km *KeyManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, km.JWKS())
	}
}

// ---------------------------------------------------------------------------
// Authorize
// ---------------------------------------------------------------------------

func authorizeHandler(dep RouterDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		clientID := strings.TrimSpace(q.Get("client_id"))
		redirectURI := strings.TrimSpace(q.Get("redirect_uri"))
		responseType := strings.TrimSpace(q.Get("response_type"))
		scope := strings.TrimSpace(q.Get("scope"))
		state := strings.TrimSpace(q.Get("state"))
		nonce := strings.TrimSpace(q.Get("nonce"))
		challenge := strings.TrimSpace(q.Get("code_challenge"))
		challengeMethod := strings.TrimSpace(q.Get("code_challenge_method"))

		if clientID == "" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "client_id is required")
			return
		}
		if redirectURI == "" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri is required")
			return
		}
		if responseType != "code" {
			redirectWithError(w, r, redirectURI, state, "unsupported_response_type", "only 'code' is supported")
			return
		}
		if challenge == "" {
			redirectWithError(w, r, redirectURI, state, "invalid_request", "code_challenge is required (PKCE mandatory)")
			return
		}
		if challengeMethod != "" && !strings.EqualFold(challengeMethod, "S256") {
			redirectWithError(w, r, redirectURI, state, "invalid_request", "code_challenge_method must be S256 (plain is not supported)")
			return
		}

		scopes := splitScope(scope)

		now := time.Now().UTC()
		flow := domain.Flow{
			ID:            fmt.Sprintf("flow_%d", now.UnixNano()),
			State:         string(flowengine.StateInitiated),
			Scenario:      string(flowengine.ScenarioNormal),
			Protocol:      "oidc",
			ClientID:      clientID,
			RedirectURI:   redirectURI,
			Scopes:        scopes,
			ResponseType:  responseType,
			OAuthState:    state,
			Nonce:         nonce,
			PKCEChallenge: challenge,
			PKCEMethod:    challengeMethod,
			CreatedAt:     now,
			ExpiresAt:     now.Add(30 * time.Minute),
		}

		created, err := dep.Flows.Create(flow)
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to create flow")
			return
		}

		loginURL := dep.LoginURL + "?flow_id=" + created.ID
		http.Redirect(w, r, loginURL, http.StatusFound)
	}
}

// ---------------------------------------------------------------------------
// Authorize Complete — called by the login UI after the flow reaches complete.
// ---------------------------------------------------------------------------

func authorizeCompleteHandler(dep RouterDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flowID := strings.TrimSpace(r.URL.Query().Get("flow_id"))
		if flowID == "" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "flow_id is required")
			return
		}

		flow, err := dep.Flows.GetByID(flowID)
		if err != nil {
			writeOAuthError(w, http.StatusNotFound, "invalid_request", "flow not found")
			return
		}
		if flow.State != string(flowengine.StateComplete) {
			writeOAuthError(w, http.StatusConflict, "invalid_request", "flow is not complete")
			return
		}
		if flow.RedirectURI == "" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "flow has no redirect_uri (not an OIDC flow)")
			return
		}

		// Generate auth code and store it on the flow.
		code, err := randomID(16)
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to generate auth code")
			return
		}
		flow.AuthCode = code
		if _, err := dep.Flows.Update(flow); err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to store auth code")
			return
		}

		redirectTo, _ := url.Parse(flow.RedirectURI)
		q := redirectTo.Query()
		q.Set("code", code)
		if flow.OAuthState != "" {
			q.Set("state", flow.OAuthState)
		}
		redirectTo.RawQuery = q.Encode()
		http.Redirect(w, r, redirectTo.String(), http.StatusFound)
	}
}

// ---------------------------------------------------------------------------
// Token
// ---------------------------------------------------------------------------

func tokenHandler(dep RouterDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "cannot parse form")
			return
		}

		grantType := strings.TrimSpace(r.FormValue("grant_type"))

		switch grantType {
		case "authorization_code":
			handleAuthCodeGrant(w, r, dep)
		case "refresh_token":
			handleRefreshGrant(w, r, dep)
		default:
			writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "supported: authorization_code, refresh_token")
		}
	}
}

func handleAuthCodeGrant(w http.ResponseWriter, r *http.Request, dep RouterDeps) {
	code := strings.TrimSpace(r.FormValue("code"))
	redirectURI := strings.TrimSpace(r.FormValue("redirect_uri"))
	verifier := strings.TrimSpace(r.FormValue("code_verifier"))

	if code == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code is required")
		return
	}

	// Atomically consume the auth code: ConsumeAuthCode clears it in storage
	// and returns the flow. Concurrent redemption attempts: exactly one wins.
	matched, err := dep.Flows.ConsumeAuthCode(code)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "code not found or already redeemed")
		return
	}
	if matched.State != string(flowengine.StateComplete) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "flow is not complete")
		return
	}
	if time.Now().UTC().After(matched.ExpiresAt) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code expired")
		return
	}
	if redirectURI != "" && redirectURI != matched.RedirectURI {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}

	if err := VerifyPKCE(matched.PKCEChallenge, matched.PKCEMethod, verifier); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", err.Error())
		return
	}

	user, err := dep.Users.GetByID(matched.UserID)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "user not found")
		return
	}

	// Check expired_token scenario — issue a token that expires immediately.
	flow := matched
	issuer := dep.Issuer
	if flowengine.NormalizeScenario(flow.Scenario) == flowengine.ScenarioExpiredToken {
		// Temporarily swap in a 0-second TTL config for this issuance.
		expiredIssuer := NewIssuer(dep.KeyMgr, TokenConfig{
			AccessTokenTTL:  -1 * time.Second,
			IDTokenTTL:      -1 * time.Second,
			RefreshTokenTTL: dep.Issuer.tokenConfig().RefreshTokenTTL,
		}, dep.Issuer.issuer)
		issuer = expiredIssuer
	}

	tokens, err := issuer.Issue(flow, user)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "token issuance failed")
		return
	}

	// Create a session record, binding the refresh token to it.
	now := time.Now().UTC()
	session := domain.Session{
		ID:           fmt.Sprintf("sess_%d", now.UnixNano()),
		UserID:       matched.UserID,
		FlowID:       matched.ID,
		Protocol:     matched.Protocol,
		ClientID:     matched.ClientID,
		RefreshToken: hashRefreshToken(tokens.RefreshToken, dep.SessionHashKey),
		CreatedAt:    now,
		ExpiresAt:    now.Add(dep.Issuer.tokenConfig().RefreshTokenTTL),
		Events: []domain.SessionEvent{
			{Timestamp: now, Type: "token_issued"},
		},
	}
	_, _ = dep.Sessions.Create(session)

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, tokens)
}

func handleRefreshGrant(w http.ResponseWriter, r *http.Request, dep RouterDeps) {
	incomingToken := strings.TrimSpace(r.FormValue("refresh_token"))
	if incomingToken == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}

	session, err := dep.Sessions.GetByRefreshToken(hashRefreshToken(incomingToken, dep.SessionHashKey))
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token not found or already rotated")
		return
	}
	if time.Now().UTC().After(session.ExpiresAt) {
		_ = dep.Sessions.Delete(session.ID)
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token expired")
		return
	}

	user, err := dep.Users.GetByID(session.UserID)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "user not found")
		return
	}

	// Build a synthetic flow for token issuance (no PKCE, no auth code needed).
	flow := domain.Flow{
		UserID:   session.UserID,
		ClientID: "", // refresh grants don't carry client_id in this dev context
	}
	tokens, err := dep.Issuer.Issue(flow, user)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "token issuance failed")
		return
	}

	// Rotate: replace the old refresh token on the session.
	session.RefreshToken = hashRefreshToken(tokens.RefreshToken, dep.SessionHashKey)
	session.ExpiresAt = time.Now().UTC().Add(dep.Issuer.tokenConfig().RefreshTokenTTL)
	session.Events = append(session.Events, domain.SessionEvent{
		Timestamp: time.Now().UTC(),
		Type:      "refreshed",
	})
	_, _ = dep.Sessions.Update(session)

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, tokens)
}

// ---------------------------------------------------------------------------
// Userinfo
// ---------------------------------------------------------------------------

func userinfoHandler(dep RouterDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="furnace"`)
			writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "bearer token required")
			return
		}

		// Parse the JWT to get the sub claim (we trust our own signature here
		// since this is a local dev tool — full validation is optional).
		sub, err := subFromJWT(token)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="furnace", error="invalid_token"`)
			writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "cannot parse access token")
			return
		}

		user, err := dep.Users.GetByID(sub)
		if err != nil {
			writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "user not found")
			return
		}

		claims := map[string]any{
			"sub":   user.ID,
			"email": user.Email,
			"name":  user.DisplayName,
		}
		if len(user.Groups) > 0 {
			claims["groups"] = user.Groups
		}
		for k, v := range user.Claims {
			if _, exists := claims[k]; !exists {
				claims[k] = v
			}
		}

		if dep.HeaderPropagation {
			if len(dep.HeaderMappings) > 0 {
				for _, m := range dep.HeaderMappings {
					if val := resolveHeaderClaim(claims, m.Claim, m.Join); val != "" {
						w.Header().Set(m.Name, val)
					}
				}
			} else {
				w.Header().Set("X-User-ID", user.ID)
				w.Header().Set("X-User-Email", user.Email)
				w.Header().Set("X-User-Groups", strings.Join(user.Groups, ","))
			}
		}

		writeJSON(w, http.StatusOK, claims)
	}
}

// ---------------------------------------------------------------------------
// Introspect — RFC 7662
// ---------------------------------------------------------------------------

// resolveHeaderClaim extracts a claim value from the userinfo map and returns
// it as a string. []any values are joined with sep (defaulting to ",").
func resolveHeaderClaim(claims map[string]any, key, sep string) string {
	if sep == "" {
		sep = ","
	}
	v, ok := claims[key]
	if !ok {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case []any:
		parts := make([]string, 0, len(val))
		for _, s := range val {
			parts = append(parts, fmt.Sprint(s))
		}
		return strings.Join(parts, sep)
	default:
		return fmt.Sprint(val)
	}
}

// introspectHandler implements POST /oauth2/introspect (RFC 7662).
// No auth is required — the endpoint is designed for reverse-proxy use cases
// (e.g. nginx auth_request) that cannot perform local JWT validation.
// An invalid or expired token returns {"active":false}, not an HTTP error.
func introspectHandler(dep RouterDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "cannot parse form")
			return
		}

		token := strings.TrimSpace(r.FormValue("token"))
		if token == "" {
			writeJSON(w, http.StatusOK, map[string]any{"active": false})
			return
		}

		claims, active, err := dep.KeyMgr.VerifyJWT(token)
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "token verification failed")
			return
		}
		if !active || claims == nil {
			writeJSON(w, http.StatusOK, map[string]any{"active": false})
			return
		}

		// Build the RFC 7662 response from the verified claims.
		resp := map[string]any{"active": true}

		if sub, _ := claims["sub"].(string); sub != "" {
			resp["sub"] = sub
			// Enrich with live user data so the response reflects the current
			// state of the user record (groups may have changed since issuance).
			if user, err := dep.Users.GetByID(sub); err == nil {
				resp["username"] = user.Email
				resp["email"] = user.Email
				if len(user.Groups) > 0 {
					resp["groups"] = user.Groups
				}
				for k, v := range user.Claims {
					if _, exists := resp[k]; !exists {
						resp[k] = v
					}
				}
			}
		}
		if aud, ok := claims["aud"]; ok {
			resp["client_id"] = aud
		}
		if exp, ok := claims["exp"]; ok {
			resp["exp"] = exp
		}
		if scope, ok := claims["scope"].(string); ok && scope != "" {
			resp["scope"] = scope
		}

		writeJSON(w, http.StatusOK, resp)
	}
}

// ---------------------------------------------------------------------------
// Revoke
// ---------------------------------------------------------------------------

func revokeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Accept and ignore — tokens are short-lived in a dev context.
		w.WriteHeader(http.StatusOK)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return strings.TrimSpace(r.FormValue("access_token"))
}

// subFromJWT extracts the "sub" claim from an unsecured/signed JWT without
// verifying the signature (acceptable for a local dev server).
func subFromJWT(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid jwt format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("unmarshal claims: %w", err)
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return "", fmt.Errorf("sub claim missing")
	}
	return sub, nil
}


func splitScope(scope string) []string {
	if scope == "" {
		return nil
	}
	parts := strings.Fields(scope)
	return parts
}

func redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, state, errCode, desc string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, errCode, desc)
		return
	}
	q := u.Query()
	q.Set("error", errCode)
	q.Set("error_description", desc)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeOAuthError(w http.ResponseWriter, status int, errCode, desc string) {
	writeJSON(w, status, map[string]string{
		"error":             errCode,
		"error_description": desc,
	})
}
