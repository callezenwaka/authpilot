package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

// VerifyPKCE checks the code_verifier against the stored challenge.
func VerifyPKCE(challenge, method, verifier string) error {
	if challenge == "" {
		return errors.New("pkce challenge is missing")
	}
	if verifier == "" {
		return errors.New("code_verifier is required")
	}

	switch strings.ToUpper(method) {
	case "S256", "":
		h := sha256.Sum256([]byte(verifier))
		derived := base64.RawURLEncoding.EncodeToString(h[:])
		if derived != challenge {
			return errors.New("pkce verification failed")
		}
	default:
		return errors.New("unsupported code_challenge_method (S256 required)")
	}
	return nil
}
