package oidc

import (
	"encoding/json"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v3"

	"authpilot/server/internal/domain"
)

// TokenConfig controls lifetimes for issued tokens.
type TokenConfig struct {
	AccessTokenTTL  time.Duration
	IDTokenTTL      time.Duration
	RefreshTokenTTL time.Duration
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
	km     *KeyManager
	cfg    TokenConfig
	issuer string // e.g. "http://localhost:8026"
}

func NewIssuer(km *KeyManager, cfg TokenConfig, issuerURL string) *Issuer {
	return &Issuer{km: km, cfg: cfg, issuer: issuerURL}
}

// Issue mints an access token, ID token, and refresh token for the given flow+user.
func (i *Issuer) Issue(flow domain.Flow, user domain.User) (TokenSet, error) {
	now := time.Now().UTC()

	signer, err := i.km.Signer()
	if err != nil {
		return TokenSet{}, fmt.Errorf("get signer: %w", err)
	}

	accessToken, err := i.signJWT(signer, map[string]any{
		"iss": i.issuer,
		"sub": user.ID,
		"aud": flow.ClientID,
		"iat": now.Unix(),
		"exp": now.Add(i.cfg.AccessTokenTTL).Unix(),
	})
	if err != nil {
		return TokenSet{}, fmt.Errorf("sign access token: %w", err)
	}

	idClaims := map[string]any{
		"iss":   i.issuer,
		"sub":   user.ID,
		"aud":   flow.ClientID,
		"iat":   now.Unix(),
		"exp":   now.Add(i.cfg.IDTokenTTL).Unix(),
		"email": user.Email,
		"name":  user.DisplayName,
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

	idToken, err := i.signJWT(signer, idClaims)
	if err != nil {
		return TokenSet{}, fmt.Errorf("sign id token: %w", err)
	}

	refreshToken, err := randomID(32)
	if err != nil {
		return TokenSet{}, fmt.Errorf("generate refresh token: %w", err)
	}

	scopeStr := ""
	if len(flow.Scopes) > 0 {
		for idx, s := range flow.Scopes {
			if idx > 0 {
				scopeStr += " "
			}
			scopeStr += s
		}
	}

	return TokenSet{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(i.cfg.AccessTokenTTL.Seconds()),
		IDToken:      idToken,
		RefreshToken: refreshToken,
		Scope:        scopeStr,
	}, nil
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
	ttl := i.cfg.AccessTokenTTL
	if expiresIn > 0 {
		ttl = time.Duration(expiresIn) * time.Second
	}

	now := time.Now().UTC()
	signer, err := i.km.Signer()
	if err != nil {
		return MintedTokens{}, fmt.Errorf("get signer: %w", err)
	}

	accessToken, err := i.signJWT(signer, map[string]any{
		"iss": i.issuer,
		"sub": user.ID,
		"aud": clientID,
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
	})
	if err != nil {
		return MintedTokens{}, fmt.Errorf("sign access token: %w", err)
	}

	idClaims := map[string]any{
		"iss":   i.issuer,
		"sub":   user.ID,
		"aud":   clientID,
		"iat":   now.Unix(),
		"exp":   now.Add(ttl).Unix(),
		"email": user.Email,
		"name":  user.DisplayName,
	}
	if len(user.Groups) > 0 {
		idClaims["groups"] = user.Groups
	}
	for k, v := range user.Claims {
		if _, exists := idClaims[k]; !exists {
			idClaims[k] = v
		}
	}

	idToken, err := i.signJWT(signer, idClaims)
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
