// Package password provides password hashing and verification for the
// /platform/* authentication endpoints.
//
// Primary algorithm: argon2id with OWASP-recommended parameters, stored in
// PHC string format so the parameters travel with the hash and upgrades are
// automatic on next successful login.
//
// Bcrypt compatibility: hashes starting with "$2" are recognised as bcrypt
// and verified with bcrypt.CompareHashAndPassword. On success Verify sets
// rehashNeeded=true so the caller can re-hash with argon2id before saving.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// Argon2id parameters. Pinned so existing hashes remain verifiable after a
// parameter bump — the PHC string carries the parameters used at hash time,
// and Verify reads them back on every call.
//
// Values meet OWASP minimum (2025):
//   m=65536 (64 MiB), t=1 iteration, p=4 threads, salt=16 B, key=32 B
const (
	argonMemory      uint32 = 64 * 1024 // KiB
	argonIterations  uint32 = 1
	argonParallelism uint8  = 4
	argonSaltLen            = 16
	argonKeyLen      uint32 = 32
)

// ErrMismatch is returned by Verify when the password does not match the hash.
var ErrMismatch = errors.New("password: hash and password do not match")

// Hash derives an argon2id hash of password and returns the PHC string.
// The PHC format is:
//
//	$argon2id$v=19$m=<mem>,t=<iter>,p=<par>$<b64-salt>$<b64-key>
func Hash(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("password: generate salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonIterations, argonMemory, argonParallelism, argonKeyLen)
	return encodePHC(salt, key, argonMemory, argonIterations, argonParallelism), nil
}

// Verify checks password against the stored hash.
//
//   - Returns (true, false, nil) when the password matches and parameters are current.
//   - Returns (true, true, nil) when the password matches but the hash uses
//     outdated parameters (bcrypt, or old argon2id parameters) — the caller
//     should re-hash and save the new hash.
//   - Returns (false, false, ErrMismatch) when the password is wrong.
//   - Returns (false, false, err) for any other error (malformed hash, etc.).
func Verify(hash, password string) (match bool, rehashNeeded bool, err error) {
	if strings.HasPrefix(hash, "$2") {
		return verifyBcrypt(hash, password)
	}
	return verifyArgon2id(hash, password)
}

func verifyArgon2id(hash, password string) (bool, bool, error) {
	mem, iter, par, salt, key, err := decodePHC(hash)
	if err != nil {
		return false, false, fmt.Errorf("password: decode hash: %w", err)
	}
	candidate := argon2.IDKey([]byte(password), salt, iter, mem, par, uint32(len(key)))
	if subtle.ConstantTimeCompare(candidate, key) != 1 {
		return false, false, ErrMismatch
	}
	// Parameters have drifted if stored values differ from current constants.
	outdated := mem != argonMemory || iter != argonIterations || par != argonParallelism || uint32(len(key)) != argonKeyLen
	return true, outdated, nil
}

func verifyBcrypt(hash, password string) (bool, bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return false, false, ErrMismatch
	}
	if err != nil {
		return false, false, fmt.Errorf("password: bcrypt verify: %w", err)
	}
	// bcrypt matched — signal that the caller should re-hash with argon2id.
	return true, true, nil
}

// encodePHC serialises the hash components into PHC string format.
func encodePHC(salt, key []byte, mem, iter uint32, par uint8) string {
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		mem, iter, par,
		b64.EncodeToString(salt),
		b64.EncodeToString(key),
	)
}

// decodePHC parses a PHC string produced by encodePHC.
func decodePHC(s string) (mem, iter uint32, par uint8, salt, key []byte, err error) {
	// Expected: $argon2id$v=19$m=<mem>,t=<iter>,p=<par>$<salt>$<key>
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return 0, 0, 0, nil, nil, errors.New("not an argon2id PHC string")
	}
	var version int
	if _, e := fmt.Sscanf(parts[2], "v=%d", &version); e != nil || version != 19 {
		return 0, 0, 0, nil, nil, errors.New("unsupported argon2id version")
	}
	var p uint8
	if _, e := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &iter, &p); e != nil {
		return 0, 0, 0, nil, nil, fmt.Errorf("parse argon2id params: %w", e)
	}
	par = p
	b64 := base64.RawStdEncoding
	if salt, err = b64.DecodeString(parts[4]); err != nil {
		return 0, 0, 0, nil, nil, fmt.Errorf("decode salt: %w", err)
	}
	if key, err = b64.DecodeString(parts[5]); err != nil {
		return 0, 0, 0, nil, nil, fmt.Errorf("decode key: %w", err)
	}
	return mem, iter, par, salt, key, nil
}
