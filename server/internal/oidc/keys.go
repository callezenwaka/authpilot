package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// keyRSABits is the RSA modulus length for newly generated signing keys.
// 3072 is the NIST minimum for new long-term signing keys; 2048 is acceptable
// only for transitional deployments. See spec-v3.md §1.3.
const keyRSABits = 3072

// defaultKeyOverlap is the JWKS overlap window used when no explicit value
// is configured. 24h exceeds typical JWKS cache TTLs (1h–24h in the wild),
// ensuring in-flight tokens remain verifiable after a rotation.
const defaultKeyOverlap = 24 * time.Hour

// keyEntry is one signing key tracked by the manager. The active key has
// retiredAt == zero; older entries carry the time they were retired so the
// manager can prune them after the overlap window elapses.
type keyEntry struct {
	private   *rsa.PrivateKey
	kid       string
	publicJWK jose.JSONWebKey
	retiredAt time.Time
}

// KeyManagerOption is a functional option for KeyManager construction.
type KeyManagerOption func(*KeyManager)

// WithKeyGenerator overrides the RSA key generator. Intended for tests that
// need fast key generation; production code should not use this option.
func WithKeyGenerator(gen func() (*rsa.PrivateKey, error)) KeyManagerOption {
	return func(km *KeyManager) { km.keyGen = gen }
}

// KeyManager holds the active RSA signing key plus any retired keys that are
// still inside the JWKS overlap window. The active key signs all new tokens;
// retired keys remain published in JWKS so previously-issued tokens continue
// to verify until they expire (or until the overlap window closes).
type KeyManager struct {
	mu      sync.RWMutex
	active  *keyEntry
	keys    []*keyEntry // active + retired-but-still-published, newest first
	overlap time.Duration
	keyGen  func() (*rsa.PrivateKey, error)
}

// NewKeyManager returns a KeyManager with the default 24h overlap window.
func NewKeyManager() (*KeyManager, error) {
	return NewKeyManagerWithOverlap(defaultKeyOverlap)
}

// NewKeyManagerWithOverlap returns a KeyManager with a configurable overlap
// window. Use this when FURNACE_KEY_ROTATION_OVERLAP is configured.
func NewKeyManagerWithOverlap(overlap time.Duration, opts ...KeyManagerOption) (*KeyManager, error) {
	if overlap < 0 {
		overlap = 0
	}
	km := &KeyManager{
		overlap: overlap,
		keyGen:  func() (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, keyRSABits) },
	}
	for _, opt := range opts {
		opt(km)
	}
	if err := km.Rotate(); err != nil {
		return nil, err
	}
	return km, nil
}

// Rotate generates a new RSA signing key, demotes the previously-active key
// to retired status (still published in JWKS for the overlap window), and
// prunes any retired keys whose overlap window has elapsed. The new key is
// the active signer; retired keys are verify-only.
func (km *KeyManager) Rotate() error {
	priv, err := km.keyGen()
	if err != nil {
		return fmt.Errorf("generate rsa key: %w", err)
	}
	kid, err := randomID(8)
	if err != nil {
		return fmt.Errorf("generate key id: %w", err)
	}
	entry := &keyEntry{
		private: priv,
		kid:     kid,
		publicJWK: jose.JSONWebKey{
			Key:       &priv.PublicKey,
			KeyID:     kid,
			Algorithm: string(jose.RS256),
			Use:       "sig",
		},
	}

	now := time.Now().UTC()
	km.mu.Lock()
	defer km.mu.Unlock()

	// Mark the previously-active key retired (kept in km.keys).
	if km.active != nil {
		km.active.retiredAt = now
	}

	// Prune retired keys whose overlap window has elapsed.
	pruned := km.keys[:0]
	for _, k := range km.keys {
		if k.retiredAt.IsZero() || now.Sub(k.retiredAt) < km.overlap {
			pruned = append(pruned, k)
		}
	}

	// Newest first.
	km.active = entry
	km.keys = append([]*keyEntry{entry}, pruned...)
	return nil
}

// StartRotation starts a background goroutine that calls Rotate on the given
// interval until ctx is cancelled. onRotate is called after each attempt (nil
// on success, the error on failure). A zero or negative interval is a no-op.
func (km *KeyManager) StartRotation(ctx context.Context, interval time.Duration, onRotate func(error)) {
	if interval <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				onRotate(km.Rotate())
			}
		}
	}()
}

// Signer returns a JWS signer for the active key. Retired keys are verify-only.
func (km *KeyManager) Signer() (jose.Signer, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()
	if km.active == nil {
		return nil, fmt.Errorf("no active signing key")
	}
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: km.active.private},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", km.active.kid),
	)
	if err != nil {
		return nil, fmt.Errorf("new signer: %w", err)
	}
	return sig, nil
}

// JWKS returns the public key set for the /.well-known/jwks.json endpoint.
// Includes the active key plus any retired keys still inside the overlap window.
func (km *KeyManager) JWKS() jose.JSONWebKeySet {
	km.mu.RLock()
	defer km.mu.RUnlock()
	out := jose.JSONWebKeySet{Keys: make([]jose.JSONWebKey, 0, len(km.keys))}
	for _, k := range km.keys {
		out.Keys = append(out.Keys, k.publicJWK)
	}
	return out
}

// VerifyJWT parses and verifies a compact JWS token signed by the active key.
// Returns the decoded claims map and whether the token is currently active
// (signature valid and not expired). A parse error returns (nil, false, nil);
// a crypto error returns (nil, false, err).
func (km *KeyManager) VerifyJWT(token string) (claims map[string]any, active bool, err error) {
	pubKey := km.JWKS()

	// Build a verifier from the published public keys.
	jws, parseErr := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if parseErr != nil {
		return nil, false, nil // unparseable → inactive, not an error
	}

	// Try each key in the set.
	var payload []byte
	for _, k := range pubKey.Keys {
		if p, verifyErr := jws.Verify(k); verifyErr == nil {
			payload = p
			break
		}
	}
	if payload == nil {
		return nil, false, nil // signature invalid → inactive
	}

	var c map[string]any
	if jsonErr := json.Unmarshal(payload, &c); jsonErr != nil {
		return nil, false, fmt.Errorf("unmarshal claims: %w", jsonErr)
	}

	// Check expiry.
	active = true
	if expRaw, ok := c["exp"]; ok {
		var expUnix float64
		switch v := expRaw.(type) {
		case float64:
			expUnix = v
		case json.Number:
			expUnix, _ = v.Float64()
		}
		if expUnix > 0 && time.Now().UTC().After(time.Unix(int64(expUnix), 0)) {
			active = false
		}
	}

	// Normalise scope: space-delimited string or array → string.
	if sc, ok := c["scope"]; ok {
		switch v := sc.(type) {
		case []any:
			parts := make([]string, 0, len(v))
			for _, s := range v {
				parts = append(parts, fmt.Sprint(s))
			}
			c["scope"] = strings.Join(parts, " ")
		}
	}

	return c, active, nil
}
