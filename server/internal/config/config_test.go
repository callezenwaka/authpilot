package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConfigPrecedenceRuntimeOverEnvOverYAMLOverDefaults(t *testing.T) {
	t.Setenv("AUTHPILOT_HTTP_ADDR", ":9001")
	t.Setenv("AUTHPILOT_PERSISTENCE_ENABLED", "true")

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
	yaml := `
- id: usr_alice
  email: alice@example.com
  display_name: Alice
  mfa_method: totp
- id: usr_bob
  email: bob@example.com
`
	t.Setenv("AUTHPILOT_SEED_USERS", yaml)

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
	t.Setenv("AUTHPILOT_SEED_USERS", "}{not yaml}{")

	_, err := Load("", RuntimeOverrides{})
	if err == nil {
		t.Fatal("expected error for invalid AUTHPILOT_SEED_USERS YAML")
	}
}

func boolPtr(v bool) *bool {
	return &v
}
