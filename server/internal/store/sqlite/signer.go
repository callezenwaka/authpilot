package sqlite

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
)

// policySigner generates and verifies ed25519 signatures over policy content hashes.
// The private key is generated once on first use and persisted in furnace_settings so
// that signatures survive server restarts.
type policySigner struct {
	privKey ed25519.PrivateKey
	pubKey  ed25519.PublicKey
}

// loadOrCreateSigner loads the ed25519 signing key from furnace_settings, or
// generates a new one and persists it if none exists.
func loadOrCreateSigner(db *sql.DB) (*policySigner, error) {
	var encoded string
	err := db.QueryRow(`SELECT value FROM furnace_settings WHERE key = 'policy_signing_key'`).Scan(&encoded)
	if err == sql.ErrNoRows {
		pub, priv, genErr := ed25519.GenerateKey(rand.Reader)
		if genErr != nil {
			return nil, fmt.Errorf("generate policy signing key: %w", genErr)
		}
		encoded = base64.StdEncoding.EncodeToString(priv)
		if _, insertErr := db.Exec(
			`INSERT INTO furnace_settings (key, value) VALUES ('policy_signing_key', ?)`, encoded,
		); insertErr != nil {
			return nil, fmt.Errorf("persist policy signing key: %w", insertErr)
		}
		return &policySigner{privKey: priv, pubKey: pub}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load policy signing key: %w", err)
	}
	raw, decErr := base64.StdEncoding.DecodeString(encoded)
	if decErr != nil {
		return nil, fmt.Errorf("decode policy signing key: %w", decErr)
	}
	priv := ed25519.PrivateKey(raw)
	return &policySigner{privKey: priv, pubKey: priv.Public().(ed25519.PublicKey)}, nil
}

// sign returns a base64-encoded ed25519 signature of message.
func (ps *policySigner) sign(message string) string {
	sig := ed25519.Sign(ps.privKey, []byte(message))
	return base64.StdEncoding.EncodeToString(sig)
}

// verify returns true when signature is a valid ed25519 signature of message under ps.pubKey.
func (ps *policySigner) verify(message, signature string) bool {
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false
	}
	return ed25519.Verify(ps.pubKey, []byte(message), sig)
}
