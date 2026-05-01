package oidc_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"sync/atomic"
	"testing"
	"time"

	"furnace/server/internal/oidc"
)

// testKeyBits is the minimum RSA key size Go accepts (1024-bit).
// Production code always uses keyRSABits (3072); this is only for test speed.
const testKeyBits = 1024

// testRotationInterval is the ticker period for StartRotation tests.
// Small enough that multiple rotations happen within testRotationTimeout.
const testRotationInterval = 5 * time.Millisecond

// testRotationTimeout is the upper bound for StartRotation tests.
const testRotationTimeout = 200 * time.Millisecond

// fastKeyGen returns a KeyManagerOption that uses small RSA keys for speed.
func fastKeyGen() oidc.KeyManagerOption {
	return oidc.WithKeyGenerator(func() (*rsa.PrivateKey, error) {
		return rsa.GenerateKey(rand.Reader, testKeyBits)
	})
}

// newFastKM creates a KeyManager that generates RSA-512 keys (test-only).
func newFastKM(t *testing.T, overlap time.Duration) *oidc.KeyManager {
	t.Helper()
	km, err := oidc.NewKeyManagerWithOverlap(overlap, fastKeyGen())
	if err != nil {
		t.Fatalf("NewKeyManagerWithOverlap: %v", err)
	}
	return km
}

// --- Rotate unit tests ---

func TestKeyManager_InitialKeyInJWKS(t *testing.T) {
	km, err := oidc.NewKeyManager()
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	if len(km.JWKS().Keys) == 0 {
		t.Error("expected at least one key in JWKS after init")
	}
}

func TestKeyManager_RotateChangesActiveKey(t *testing.T) {
	km := newFastKM(t, 0)
	before := km.JWKS().Keys[0].KeyID

	if err := km.Rotate(); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	after := km.JWKS().Keys[0].KeyID
	if before == after {
		t.Error("key ID should change after rotation")
	}
}

func TestKeyManager_RetiredKeyRemainsInJWKSWithinOverlap(t *testing.T) {
	const overlap = 1 * time.Hour
	km := newFastKM(t, overlap)
	oldKID := km.JWKS().Keys[0].KeyID

	if err := km.Rotate(); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	var found bool
	for _, k := range km.JWKS().Keys {
		if k.KeyID == oldKID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("old key %q should still be in JWKS within overlap window", oldKID)
	}
}

func TestKeyManager_RetiredKeyPrunedWithZeroOverlap(t *testing.T) {
	km := newFastKM(t, 0)
	oldKID := km.JWKS().Keys[0].KeyID

	if err := km.Rotate(); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	for _, k := range km.JWKS().Keys {
		if k.KeyID == oldKID {
			t.Errorf("old key %q should have been pruned with 0 overlap", oldKID)
		}
	}
	if n := len(km.JWKS().Keys); n != 1 {
		t.Errorf("expected exactly 1 key after zero-overlap rotation, got %d", n)
	}
}

func TestKeyManager_TokenSignedWithOldKeyVerifiesAfterRotation(t *testing.T) {
	const overlap = 1 * time.Hour
	km := newFastKM(t, overlap)

	signer, err := km.Signer()
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	// far-future exp so the token is always active during the test
	payload := `{"sub":"usr_test","exp":9999999999}`
	jws, err := signer.Sign([]byte(payload))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	token, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize: %v", err)
	}

	// Rotate to a new key — old key is still in JWKS overlap window.
	if err := km.Rotate(); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	claims, active, err := km.VerifyJWT(token)
	if err != nil {
		t.Fatalf("VerifyJWT after rotation: %v", err)
	}
	if claims == nil || !active {
		t.Error("token signed with retired key should still be active within overlap window")
	}
}

// --- StartRotation tests ---

func TestKeyManager_StartRotation_RotatesOnInterval(t *testing.T) {
	km := newFastKM(t, 0)
	initial := km.JWKS().Keys[0].KeyID

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var rotations atomic.Int32
	km.StartRotation(ctx, testRotationInterval, func(err error) {
		if err == nil {
			rotations.Add(1)
		}
	})

	deadline := time.Now().Add(testRotationTimeout)
	for time.Now().Before(deadline) {
		if rotations.Load() >= 2 {
			break
		}
		time.Sleep(testRotationInterval)
	}
	if rotations.Load() < 2 {
		t.Errorf("expected ≥2 rotations in %v, got %d", testRotationTimeout, rotations.Load())
	}

	current := km.JWKS().Keys[0].KeyID
	if current == initial {
		t.Error("active key ID should have changed after rotation")
	}
}

func TestKeyManager_StartRotation_ZeroIntervalIsNoop(t *testing.T) {
	km := newFastKM(t, 0)
	initial := km.JWKS().Keys[0].KeyID

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var called atomic.Bool
	km.StartRotation(ctx, 0, func(error) { called.Store(true) })

	time.Sleep(testRotationTimeout)

	if called.Load() {
		t.Error("onRotate must not be called when interval is 0")
	}
	if km.JWKS().Keys[0].KeyID != initial {
		t.Error("key must not change when StartRotation is a no-op")
	}
}

func TestKeyManager_StartRotation_StopsOnContextCancel(t *testing.T) {
	km := newFastKM(t, 0)

	ctx, cancel := context.WithCancel(context.Background())

	var rotations atomic.Int32
	km.StartRotation(ctx, testRotationInterval, func(err error) {
		if err == nil {
			rotations.Add(1)
		}
	})

	time.Sleep(testRotationTimeout)
	before := rotations.Load()
	cancel()

	// After cancel, goroutine must stop. Allow one extra tick to drain.
	time.Sleep(testRotationInterval * 3)
	after := rotations.Load()

	if after > before+1 {
		t.Errorf("rotation continued after context cancel: before=%d after=%d", before, after)
	}
}
