package password_test

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"furnace/server/internal/platform/password"
)

func TestHash_ProducesPHCString(t *testing.T) {
	h, err := password.Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if !strings.HasPrefix(h, "$argon2id$") {
		t.Errorf("want PHC string starting with $argon2id$, got %q", h)
	}
}

func TestVerify_CorrectPassword(t *testing.T) {
	h, err := password.Hash("swordfish")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	match, rehash, err := password.Verify(h, "swordfish")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !match {
		t.Error("expected match=true for correct password")
	}
	if rehash {
		t.Error("expected rehashNeeded=false for current parameters")
	}
}

func TestVerify_WrongPassword(t *testing.T) {
	h, err := password.Hash("swordfish")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	match, _, err := password.Verify(h, "wrongpassword")
	if match {
		t.Error("expected match=false for wrong password")
	}
	if err != password.ErrMismatch {
		t.Errorf("expected ErrMismatch, got %v", err)
	}
}

func TestVerify_MalformedHash(t *testing.T) {
	_, _, err := password.Verify("not-a-hash", "password")
	if err == nil {
		t.Error("expected error for malformed hash")
	}
}

func TestVerify_BcryptUpgradePath(t *testing.T) {
	// Simulate a legacy bcrypt hash (cost 12).
	bcryptHash, err := bcrypt.GenerateFromPassword([]byte("legacy-password"), 12)
	if err != nil {
		t.Fatalf("bcrypt.GenerateFromPassword: %v", err)
	}

	match, rehash, err := password.Verify(string(bcryptHash), "legacy-password")
	if err != nil {
		t.Fatalf("Verify(bcrypt): %v", err)
	}
	if !match {
		t.Error("expected match=true for correct bcrypt password")
	}
	if !rehash {
		t.Error("expected rehashNeeded=true for bcrypt hash (upgrade to argon2id)")
	}
}

func TestVerify_BcryptWrongPassword(t *testing.T) {
	bcryptHash, err := bcrypt.GenerateFromPassword([]byte("correct"), 12)
	if err != nil {
		t.Fatalf("bcrypt.GenerateFromPassword: %v", err)
	}
	match, _, err := password.Verify(string(bcryptHash), "wrong")
	if match {
		t.Error("expected match=false for wrong bcrypt password")
	}
	if err != password.ErrMismatch {
		t.Errorf("expected ErrMismatch, got %v", err)
	}
}

func TestVerify_DifferentHashes_SamePassword(t *testing.T) {
	// Two hashes of the same password must differ (unique salts).
	h1, _ := password.Hash("same")
	h2, _ := password.Hash("same")
	if h1 == h2 {
		t.Error("two hashes of the same password must differ (salt not random)")
	}
	// Both must verify correctly.
	for _, h := range []string{h1, h2} {
		if match, _, err := password.Verify(h, "same"); !match || err != nil {
			t.Errorf("Verify(%q, same): match=%v err=%v", h, match, err)
		}
	}
}

func TestVerify_Concurrent(t *testing.T) {
	h, _ := password.Hash("concurrent-test")
	done := make(chan error, 20)
	for i := 0; i < 20; i++ {
		go func() {
			_, _, err := password.Verify(h, "concurrent-test")
			done <- err
		}()
	}
	for i := 0; i < 20; i++ {
		if err := <-done; err != nil {
			t.Errorf("concurrent Verify: %v", err)
		}
	}
}

// BenchmarkHash documents how long a single Hash call takes with the chosen
// parameters. Expected range on typical CI hardware: 50–500 ms.
func BenchmarkHash(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := password.Hash("benchmark-password"); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkVerify documents how long a single Verify call takes.
func BenchmarkVerify(b *testing.B) {
	h, err := password.Hash("benchmark-password")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := password.Verify(h, "benchmark-password"); err != nil {
			b.Fatal(err)
		}
	}
}
