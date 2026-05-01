package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// testHashKey is a deterministic 32-byte base64-encoded value used by tests
// that need to satisfy the SessionHashKey validation requirement.
const testHashKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

// testAPIKey satisfies the single-tenant APIKey requirement in tests.
const testAPIKey = "test-api-key-0123456789abcdef"

func TestConfigPrecedenceRuntimeOverEnvOverYAMLOverDefaults(t *testing.T) {
	t.Setenv("FURNACE_API_KEY", testAPIKey)
	t.Setenv("FURNACE_SESSION_HASH_KEY", testHashKey)
	t.Setenv("FURNACE_HTTP_ADDR", ":9001")
	t.Setenv("FURNACE_PERSISTENCE_ENABLED", "true")

	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "config.yaml")
	yaml := []byte(`
http_addr: ":9000"
persistence:
  enabled: false
  sqlite_path: "/tmp/from-yaml.db"
cleanup:
  interval: "30s"
`)
	if err := os.WriteFile(cfgPath, yaml, 0o644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}

	interval := 5 * time.Second
	runtime := RuntimeOverrides{
		HTTPAddr:           ":9010",
		PersistenceEnabled: boolPtr(false),
		CleanupInterval:    &interval,
	}

	cfg, err := Load(cfgPath, runtime)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.HTTPAddr != ":9010" {
		t.Fatalf("expected runtime HTTP addr, got %q", cfg.HTTPAddr)
	}
	if cfg.Persistence.Enabled {
		t.Fatalf("expected runtime persistence=false, got true")
	}
	if cfg.Persistence.SQLitePath != "/tmp/from-yaml.db" {
		t.Fatalf("expected sqlite path from yaml, got %q", cfg.Persistence.SQLitePath)
	}
	if cfg.Cleanup.Interval != 5*time.Second {
		t.Fatalf("expected cleanup interval 5s, got %v", cfg.Cleanup.Interval)
	}
}

func TestConfigValidation(t *testing.T) {
	cfg := Defaults()
	cfg.LogLevel = "nope"
	if err := validate(cfg); err == nil {
		t.Fatal("expected log level validation error")
	}
}

func TestSeedUsers_ParsedFromEnv(t *testing.T) {
	t.Setenv("FURNACE_API_KEY", testAPIKey)
	t.Setenv("FURNACE_SESSION_HASH_KEY", testHashKey)
	yaml := `
- id: usr_alice
  email: alice@example.com
  display_name: Alice
  mfa_method: totp
- id: usr_bob
  email: bob@example.com
`
	t.Setenv("FURNACE_SEED_USERS", yaml)

	cfg, err := Load("", RuntimeOverrides{})
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if len(cfg.SeedUsers) != 2 {
		t.Fatalf("expected 2 seed users, got %d", len(cfg.SeedUsers))
	}
	if cfg.SeedUsers[0].ID != "usr_alice" {
		t.Errorf("first seed user ID: want usr_alice, got %q", cfg.SeedUsers[0].ID)
	}
	if cfg.SeedUsers[1].Email != "bob@example.com" {
		t.Errorf("second seed user email: want bob@example.com, got %q", cfg.SeedUsers[1].Email)
	}
}

func TestSeedUsers_InvalidYAML_ReturnsError(t *testing.T) {
	t.Setenv("FURNACE_SEED_USERS", "}{not yaml}{")

	_, err := Load("", RuntimeOverrides{})
	if err == nil {
		t.Fatal("expected error for invalid FURNACE_SEED_USERS YAML")
	}
}

func boolPtr(v bool) *bool {
	return &v
}

// TestTenantConfigYAMLRoundtrip verifies the redaction asymmetry:
// loading a YAML config with tenant secrets populates the struct as expected
// (multi-tenant mode keeps working) but marshaling it back to YAML redacts
// the API and SCIM keys (debug dumps don't leak).
func TestTenantConfigYAMLRoundtrip(t *testing.T) {
	t.Setenv("FURNACE_SESSION_HASH_KEY", testHashKey)
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "config.yaml")
	yamlIn := []byte(`
tenancy: multi
tenants:
  - id: acme
    api_key: super-secret-api-key
    scim_key: super-secret-scim-key
    oidc_issuer_url: https://acme.example.com
`)
	if err := os.WriteFile(cfgPath, yamlIn, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(cfgPath, RuntimeOverrides{})
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if len(cfg.Tenants) != 1 {
		t.Fatalf("expected 1 tenant, got %d", len(cfg.Tenants))
	}
	if got := cfg.Tenants[0].APIKey; got != "super-secret-api-key" {
		t.Errorf("loading must populate APIKey; got %q", got)
	}
	if got := cfg.Tenants[0].SCIMKey; got != "super-secret-scim-key" {
		t.Errorf("loading must populate SCIMKey; got %q", got)
	}

	// Marshaling back must redact the secret fields.
	outBytes, err := yaml.Marshal(cfg.Tenants[0])
	if err != nil {
		t.Fatalf("marshal tenant: %v", err)
	}
	out := string(outBytes)
	if strings.Contains(out, "super-secret-api-key") {
		t.Errorf("marshaled YAML must not contain the API key:\n%s", out)
	}
	if strings.Contains(out, "super-secret-scim-key") {
		t.Errorf("marshaled YAML must not contain the SCIM key:\n%s", out)
	}
	if !strings.Contains(out, "<redacted>") {
		t.Errorf("expected <redacted> placeholder in marshaled YAML:\n%s", out)
	}
	if !strings.Contains(out, "id: acme") {
		t.Errorf("non-secret fields must round-trip:\n%s", out)
	}
}

func TestTenantConfigYAMLEmptyFieldsNotRedacted(t *testing.T) {
	tc := TenantConfig{ID: "solo"} // APIKey and SCIMKey both empty
	outBytes, err := yaml.Marshal(tc)
	if err != nil {
		t.Fatalf("marshal tenant: %v", err)
	}
	out := string(outBytes)
	if strings.Contains(out, "<redacted>") {
		t.Errorf("empty fields must not be redacted (would look like a hidden secret):\n%s", out)
	}
}
