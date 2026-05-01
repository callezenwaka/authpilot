package oidc

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"furnace/server/internal/domain"
	"furnace/server/internal/personality"
)

// HasuraClaimsConfig injects a Hasura-compatible claim namespace into the ID token.
type HasuraClaimsConfig struct {
	Enabled      bool
	Namespace    string   // defaults to "https://hasura.io/jwt/claims"
	DefaultRole  string
	AllowedRoles []string // defaults to user groups when empty
}

// TokenConfig controls lifetimes and optional claim format for issued tokens.
type TokenConfig struct {
	AccessTokenTTL  time.Duration
	IDTokenTTL      time.Duration
	RefreshTokenTTL time.Duration
	// Format flags — all default false (existing behaviour unchanged).
	IncludeJTI   bool // add jti (unique token ID) to every token
	AudAsArray   bool // emit aud as ["clientID"] instead of "clientID"
	IncludeScope bool // add scope claim to access token
	// Framework integration.
	HasuraClaims HasuraClaimsConfig
}

func DefaultTokenConfig() TokenConfig {
	return TokenConfig{
		AccessTokenTTL:  1 * time.Hour,
		IDTokenTTL:      1 * time.Hour,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	}
}

// TokenSet is the response payload for POST /token.
type TokenSet struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// Issuer builds and signs tokens for a completed flow.
type Issuer struct {
	km          *KeyManager
	cfg         atomic.Pointer[TokenConfig]
	issuer      string // e.g. "http://localhost:8026"
	personality *personality.Personality
}

func NewIssuer(km *KeyManager, cfg TokenConfig, issuerURL string) *Issuer {
	i := &Issuer{km: km, issuer: issuerURL, personality: personality.Default}
	i.cfg.Store(&cfg)
	return i
}

// SetPersonality sets the active provider personality used when building tokens.
func (i *Issuer) SetPersonality(p *personality.Personality) {
	if p == nil {
		p = personality.Default
	}
	i.personality = p
}

// GetPersonality returns the active provider personality.
func (i *Issuer) GetPersonality() *personality.Personality {
	return i.personality
}

// SetTokenConfig atomically replaces the token TTL configuration.
// Safe to call concurrently; takes effect on the next token issuance.
func (i *Issuer) SetTokenConfig(cfg TokenConfig) {
	i.cfg.Store(&cfg)
}

// tokenConfig returns the current TokenConfig snapshot (internal use).
func (i *Issuer) tokenConfig() TokenConfig {
	return *i.cfg.Load()
}

// GetTokenConfig returns the current TokenConfig snapshot (external use).
func (i *Issuer) GetTokenConfig() TokenConfig {
	return *i.cfg.Load()
}

// Issue mints an access token, ID token, and refresh token for the given flow+user.
func (i *Issuer) Issue(flow domain.Flow, user domain.User) (TokenSet, error) {
	now := time.Now().UTC()
	cfg := i.tokenConfig()

	signer, err := i.km.Signer()
	if err != nil {
		return TokenSet{}, fmt.Errorf("get signer: %w", err)
	}

	aud := audClaim(flow.ClientID, cfg.AudAsArray)
	scopeStr := strings.Join(flow.Scopes, " ")

	accessClaims := map[string]any{
		"iss": i.issuer,
		"sub": user.ID,
		"aud": aud,
		"iat": now.Unix(),
		"exp": now.Add(cfg.AccessTokenTTL).Unix(),
	}
	if cfg.IncludeJTI {
		jti, err := randomID(16)
		if err != nil {
			return TokenSet{}, fmt.Errorf("generate access token jti: %w", err)
		}
		accessClaims["jti"] = jti
	}
	if cfg.IncludeScope {
		accessClaims["scope"] = scopeStr
	}

	accessToken, err := i.signJWT(signer, accessClaims)
	if err != nil {
		return TokenSet{}, fmt.Errorf("sign access token: %w", err)
	}

	idClaims := map[string]any{
		"iss":   i.issuer,
		"sub":   user.ID,
		"aud":   aud,
		"iat":   now.Unix(),
		"exp":   now.Add(cfg.IDTokenTTL).Unix(),
		"email": user.Email,
		"name":  user.DisplayName,
	}
	if cfg.IncludeJTI {
		jti, err := randomID(16)
		if err != nil {
			return TokenSet{}, fmt.Errorf("generate id token jti: %w", err)
		}
		idClaims["jti"] = jti
	}
	if flow.Nonce != "" {
		idClaims["nonce"] = flow.Nonce
	}
	if len(user.Groups) > 0 {
		idClaims["groups"] = user.Groups
	}
	for k, v := range user.Claims {
		if _, exists := idClaims[k]; !exists {
			idClaims[k] = v
		}
	}
	applyHasuraClaims(idClaims, user, cfg.HasuraClaims)

	idToken, err := i.signJWT(signer, i.personality.Apply(idClaims))
	if err != nil {
		return TokenSet{}, fmt.Errorf("sign id token: %w", err)
	}

	refreshToken, err := randomID(32)
	if err != nil {
		return TokenSet{}, fmt.Errorf("generate refresh token: %w", err)
	}

	return TokenSet{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(cfg.AccessTokenTTL.Seconds()),
		IDToken:      idToken,
		RefreshToken: refreshToken,
		Scope:        scopeStr,
	}, nil
}

// audClaim returns aud as a bare string or single-element slice depending on cfg.
func audClaim(clientID string, asArray bool) any {
	if asArray {
		return []string{clientID}
	}
	return clientID
}

// applyHasuraClaims injects the Hasura claim namespace into idClaims when configured.
func applyHasuraClaims(idClaims map[string]any, user domain.User, cfg HasuraClaimsConfig) {
	if !cfg.Enabled {
		return
	}
	ns := cfg.Namespace
	if ns == "" {
		ns = "https://hasura.io/jwt/claims"
	}
	roles := cfg.AllowedRoles
	if len(roles) == 0 {
		roles = user.Groups
	}
	defaultRole := cfg.DefaultRole
	if defaultRole == "" && len(roles) > 0 {
		defaultRole = roles[0]
	}
	hasura := map[string]any{
		"x-hasura-default-role":  defaultRole,
		"x-hasura-allowed-roles": roles,
		"x-hasura-user-id":       user.ID,
	}
	if orgID, ok := user.Claims["org_id"].(string); ok && orgID != "" {
		hasura["x-hasura-org-id"] = orgID
	}
	idClaims[ns] = hasura
}

// MintedTokens is the response payload for POST /api/v1/tokens/mint.
type MintedTokens struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// MintForUser issues an access token and ID token for the given user directly,
// bypassing the OAuth authorization flow. Used by POST /api/v1/tokens/mint.
// expiresIn is in seconds; if ≤ 0, the issuer's AccessTokenTTL is used.
func (i *Issuer) MintForUser(user domain.User, clientID string, scopes []string, expiresIn int) (MintedTokens, error) {
	cfg := i.tokenConfig()
	ttl := cfg.AccessTokenTTL
	if expiresIn > 0 {
		ttl = time.Duration(expiresIn) * time.Second
	}

	now := time.Now().UTC()
	signer, err := i.km.Signer()
	if err != nil {
		return MintedTokens{}, fmt.Errorf("get signer: %w", err)
	}

	aud := audClaim(clientID, cfg.AudAsArray)

	accessClaims := map[string]any{
		"iss": i.issuer,
		"sub": user.ID,
		"aud": aud,
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
	}
	if cfg.IncludeJTI {
		jti, err := randomID(16)
		if err != nil {
			return MintedTokens{}, fmt.Errorf("generate access token jti: %w", err)
		}
		accessClaims["jti"] = jti
	}
	if cfg.IncludeScope && len(scopes) > 0 {
		accessClaims["scope"] = strings.Join(scopes, " ")
	}

	accessToken, err := i.signJWT(signer, accessClaims)
	if err != nil {
		return MintedTokens{}, fmt.Errorf("sign access token: %w", err)
	}

	idClaims := map[string]any{
		"iss":   i.issuer,
		"sub":   user.ID,
		"aud":   aud,
		"iat":   now.Unix(),
		"exp":   now.Add(ttl).Unix(),
		"email": user.Email,
		"name":  user.DisplayName,
	}
	if cfg.IncludeJTI {
		jti, err := randomID(16)
		if err != nil {
			return MintedTokens{}, fmt.Errorf("generate id token jti: %w", err)
		}
		idClaims["jti"] = jti
	}
	if len(user.Groups) > 0 {
		idClaims["groups"] = user.Groups
	}
	for k, v := range user.Claims {
		if _, exists := idClaims[k]; !exists {
			idClaims[k] = v
		}
	}
	applyHasuraClaims(idClaims, user, cfg.HasuraClaims)

	idToken, err := i.signJWT(signer, i.personality.Apply(idClaims))
	if err != nil {
		return MintedTokens{}, fmt.Errorf("sign id token: %w", err)
	}

	return MintedTokens{
		AccessToken: accessToken,
		IDToken:     idToken,
		ExpiresIn:   int(ttl.Seconds()),
	}, nil
}

func (i *Issuer) signJWT(signer jose.Signer, claims map[string]any) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return jws.CompactSerialize()
}
