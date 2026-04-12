package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// SeedUser is a user definition used for startup pre-seeding.
// Matches the domain.User JSON shape so the same YAML works for both.
type SeedUser struct {
	ID          string         `yaml:"id"`
	Email       string         `yaml:"email"`
	DisplayName string         `yaml:"display_name"`
	Groups      []string       `yaml:"groups"`
	MFAMethod   string         `yaml:"mfa_method"`
	NextFlow    string         `yaml:"next_flow"`
	Active      *bool          `yaml:"active"` // nil = default true
	Claims      map[string]any `yaml:"claims"`
	PhoneNumber string         `yaml:"phone_number"`
}

type Config struct {
	HTTPAddr     string            `yaml:"http_addr"`
	ProtocolAddr string            `yaml:"protocol_addr"`
	LogLevel     string            `yaml:"log_level"`
	Persistence  PersistenceConfig `yaml:"persistence"`
	Cleanup      CleanupConfig     `yaml:"cleanup"`
	OIDC         OIDCConfig        `yaml:"oidc"`
	SAML         SAMLConfig        `yaml:"saml"`
	APIKey              string            `yaml:"api_key"`              // empty = local dev mode (no auth)
	SCIMKey             string            `yaml:"scim_key"`             // separate credential for /scim/v2; falls back to APIKey when empty
	RateLimit           int               `yaml:"rate_limit"`           // requests/min per IP on /api/v1; 0 = disabled
	SeedUsers           []SeedUser        `yaml:"seed_users"`           // users created at startup; idempotent
	HeaderPropagation   bool              `yaml:"header_propagation"`   // inject X-User-* headers on /userinfo responses
}

type SAMLConfig struct {
	// EntityID is the IdP entity ID advertised in metadata.
	// Defaults to the protocol address base URL.
	EntityID string `yaml:"entity_id"`
	// CertDir is the directory where the SAML signing key and certificate are
	// persisted. If empty, a fresh ephemeral key pair is generated each startup.
	CertDir string `yaml:"cert_dir"`
}

type OIDCConfig struct {
	IssuerURL       string        `yaml:"issuer_url"`
	AccessTokenTTL  time.Duration `yaml:"access_token_ttl"`
	IDTokenTTL      time.Duration `yaml:"id_token_ttl"`
	RefreshTokenTTL time.Duration `yaml:"refresh_token_ttl"`
}

type PersistenceConfig struct {
	Enabled    bool   `yaml:"enabled"`
	SQLitePath string `yaml:"sqlite_path"`
}

type CleanupConfig struct {
	Interval   time.Duration `yaml:"interval"`
	FlowTTL    time.Duration `yaml:"flow_ttl"`
	SessionTTL time.Duration `yaml:"session_ttl"`
}

type RuntimeOverrides struct {
	HTTPAddr           string
	ProtocolAddr       string
	LogLevel           string
	SQLitePath         string
	PersistenceEnabled *bool
	CleanupInterval    *time.Duration
}

func Defaults() Config {
	return Config{
		HTTPAddr:     ":8025",
		ProtocolAddr: ":8026",
		LogLevel:     "info",
		Persistence: PersistenceConfig{
			Enabled:    false,
			SQLitePath: "./data/authpilot.db",
		},
		Cleanup: CleanupConfig{
			Interval:   60 * time.Second,
			FlowTTL:    30 * time.Minute,
			SessionTTL: 12 * time.Hour,
		},
		OIDC: OIDCConfig{
			IssuerURL:       "http://localhost:8026",
			AccessTokenTTL:  1 * time.Hour,
			IDTokenTTL:      1 * time.Hour,
			RefreshTokenTTL: 30 * 24 * time.Hour,
		},
		SAML: SAMLConfig{
			EntityID: "http://localhost:8026",
		},
	}
}

func Load(configPath string, runtime RuntimeOverrides) (Config, error) {
	cfg := Defaults()

	if configPath != "" {
		fileCfg, err := loadYAML(configPath)
		if err != nil {
			return Config{}, err
		}
		if err := mergeYAML(&cfg, fileCfg); err != nil {
			return Config{}, err
		}
	}

	if err := applyEnv(&cfg); err != nil {
		return Config{}, err
	}

	applyRuntime(&cfg, runtime)

	if err := validate(cfg); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

type yamlConfig struct {
	HTTPAddr     string               `yaml:"http_addr"`
	ProtocolAddr string               `yaml:"protocol_addr"`
	LogLevel     string               `yaml:"log_level"`
	Persistence  yamlPersistence      `yaml:"persistence"`
	Cleanup      yamlCleanupDurations `yaml:"cleanup"`
	OIDC         yamlOIDC             `yaml:"oidc"`
	SeedUsers    []SeedUser           `yaml:"seed_users"`
}

type yamlOIDC struct {
	IssuerURL       string `yaml:"issuer_url"`
	AccessTokenTTL  string `yaml:"access_token_ttl"`
	IDTokenTTL      string `yaml:"id_token_ttl"`
	RefreshTokenTTL string `yaml:"refresh_token_ttl"`
}

type yamlPersistence struct {
	Enabled    *bool  `yaml:"enabled"`
	SQLitePath string `yaml:"sqlite_path"`
}

type yamlCleanupDurations struct {
	Interval   string `yaml:"interval"`
	FlowTTL    string `yaml:"flow_ttl"`
	SessionTTL string `yaml:"session_ttl"`
}

func loadYAML(path string) (yamlConfig, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return yamlConfig{}, fmt.Errorf("read config file: %w", err)
	}

	var parsed yamlConfig
	if err := yaml.Unmarshal(content, &parsed); err != nil {
		return yamlConfig{}, fmt.Errorf("parse yaml config: %w", err)
	}
	return parsed, nil
}

func mergeYAML(cfg *Config, from yamlConfig) error {
	if from.HTTPAddr != "" {
		cfg.HTTPAddr = from.HTTPAddr
	}
	if from.ProtocolAddr != "" {
		cfg.ProtocolAddr = from.ProtocolAddr
	}
	if from.LogLevel != "" {
		cfg.LogLevel = from.LogLevel
	}
	if from.Persistence.Enabled != nil {
		cfg.Persistence.Enabled = *from.Persistence.Enabled
	}
	if from.Persistence.SQLitePath != "" {
		cfg.Persistence.SQLitePath = from.Persistence.SQLitePath
	}
	if from.Cleanup.Interval != "" {
		d, err := time.ParseDuration(from.Cleanup.Interval)
		if err != nil {
			return fmt.Errorf("yaml cleanup.interval: %w", err)
		}
		cfg.Cleanup.Interval = d
	}
	if from.Cleanup.FlowTTL != "" {
		d, err := time.ParseDuration(from.Cleanup.FlowTTL)
		if err != nil {
			return fmt.Errorf("yaml cleanup.flow_ttl: %w", err)
		}
		cfg.Cleanup.FlowTTL = d
	}
	if from.Cleanup.SessionTTL != "" {
		d, err := time.ParseDuration(from.Cleanup.SessionTTL)
		if err != nil {
			return fmt.Errorf("yaml cleanup.session_ttl: %w", err)
		}
		cfg.Cleanup.SessionTTL = d
	}
	if from.OIDC.IssuerURL != "" {
		cfg.OIDC.IssuerURL = from.OIDC.IssuerURL
	}
	if from.OIDC.AccessTokenTTL != "" {
		d, err := time.ParseDuration(from.OIDC.AccessTokenTTL)
		if err != nil {
			return fmt.Errorf("yaml oidc.access_token_ttl: %w", err)
		}
		cfg.OIDC.AccessTokenTTL = d
	}
	if from.OIDC.IDTokenTTL != "" {
		d, err := time.ParseDuration(from.OIDC.IDTokenTTL)
		if err != nil {
			return fmt.Errorf("yaml oidc.id_token_ttl: %w", err)
		}
		cfg.OIDC.IDTokenTTL = d
	}
	if from.OIDC.RefreshTokenTTL != "" {
		d, err := time.ParseDuration(from.OIDC.RefreshTokenTTL)
		if err != nil {
			return fmt.Errorf("yaml oidc.refresh_token_ttl: %w", err)
		}
		cfg.OIDC.RefreshTokenTTL = d
	}
	if len(from.SeedUsers) > 0 {
		cfg.SeedUsers = append(cfg.SeedUsers, from.SeedUsers...)
	}
	return nil
}

func applyEnv(cfg *Config) error {
	if v := strings.TrimSpace(os.Getenv("AUTHPILOT_HTTP_ADDR")); v != "" {
		cfg.HTTPAddr = v
	}
	if v := strings.TrimSpace(os.Getenv("AUTHPILOT_PROTOCOL_ADDR")); v != "" {
		cfg.ProtocolAddr = v
	}
	if v := strings.TrimSpace(os.Getenv("AUTHPILOT_LOG_LEVEL")); v != "" {
		cfg.LogLevel = v
	}
	if v := strings.TrimSpace(os.Getenv("AUTHPILOT_PERSISTENCE_ENABLED")); v != "" {
		b, err := ParseBool(v)
		if err != nil {
			return fmt.Errorf("AUTHPILOT_PERSISTENCE_ENABLED: %w", err)
		}
		cfg.Persistence.Enabled = b
	}
	if v := strings.TrimSpace(os.Getenv("AUTHPILOT_SQLITE_PATH")); v != "" {
		cfg.Persistence.SQLitePath = v
	}
	if v := strings.TrimSpace(os.Getenv("AUTHPILOT_CLEANUP_INTERVAL")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("AUTHPILOT_CLEANUP_INTERVAL: %w", err)
		}
		cfg.Cleanup.Interval = d
	}
	if v := strings.TrimSpace(os.Getenv("AUTHPILOT_FLOW_TTL")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("AUTHPILOT_FLOW_TTL: %w", err)
		}
		cfg.Cleanup.FlowTTL = d
	}
	if v := strings.TrimSpace(os.Getenv("AUTHPILOT_SESSION_TTL")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("AUTHPILOT_SESSION_TTL: %w", err)
		}
		cfg.Cleanup.SessionTTL = d
	}
	if v := strings.TrimSpace(os.Getenv("AUTHPILOT_OIDC_ISSUER_URL")); v != "" {
		cfg.OIDC.IssuerURL = v
	}
	if v := strings.TrimSpace(os.Getenv("AUTHPILOT_API_KEY")); v != "" {
		cfg.APIKey = v
	}
	if v := strings.TrimSpace(os.Getenv("AUTHPILOT_SCIM_KEY")); v != "" {
		cfg.SCIMKey = v
	}
	if v := strings.TrimSpace(os.Getenv("AUTHPILOT_RATE_LIMIT")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("AUTHPILOT_RATE_LIMIT: %w", err)
		}
		cfg.RateLimit = n
	}
	if v := strings.TrimSpace(os.Getenv("AUTHPILOT_SAML_ENTITY_ID")); v != "" {
		cfg.SAML.EntityID = v
	}
	if v := strings.TrimSpace(os.Getenv("AUTHPILOT_SAML_CERT_DIR")); v != "" {
		cfg.SAML.CertDir = v
	}
	if v := strings.TrimSpace(os.Getenv("AUTHPILOT_HEADER_PROPAGATION")); v != "" {
		b, err := ParseBool(v)
		if err != nil {
			return fmt.Errorf("AUTHPILOT_HEADER_PROPAGATION: %w", err)
		}
		cfg.HeaderPropagation = b
	}
	if v := strings.TrimSpace(os.Getenv("AUTHPILOT_SEED_USERS")); v != "" {
		var users []SeedUser
		if err := yaml.Unmarshal([]byte(v), &users); err != nil {
			return fmt.Errorf("AUTHPILOT_SEED_USERS: %w", err)
		}
		cfg.SeedUsers = append(cfg.SeedUsers, users...)
	}

	return nil
}

func applyRuntime(cfg *Config, runtime RuntimeOverrides) {
	if runtime.HTTPAddr != "" {
		cfg.HTTPAddr = runtime.HTTPAddr
	}
	if runtime.ProtocolAddr != "" {
		cfg.ProtocolAddr = runtime.ProtocolAddr
	}
	if runtime.LogLevel != "" {
		cfg.LogLevel = runtime.LogLevel
	}
	if runtime.SQLitePath != "" {
		cfg.Persistence.SQLitePath = runtime.SQLitePath
	}
	if runtime.PersistenceEnabled != nil {
		cfg.Persistence.Enabled = *runtime.PersistenceEnabled
	}
	if runtime.CleanupInterval != nil {
		cfg.Cleanup.Interval = *runtime.CleanupInterval
	}
}

func validate(cfg Config) error {
	if cfg.HTTPAddr == "" {
		return errors.New("http_addr must not be empty")
	}
	if cfg.ProtocolAddr == "" {
		return errors.New("protocol_addr must not be empty")
	}
	if !validLogLevel(cfg.LogLevel) {
		return fmt.Errorf("log_level must be one of debug|info|warn|error, got %q", cfg.LogLevel)
	}
	if cfg.Persistence.Enabled && strings.TrimSpace(cfg.Persistence.SQLitePath) == "" {
		return errors.New("persistence.sqlite_path must not be empty when persistence is enabled")
	}
	if cfg.Cleanup.Interval <= 0 {
		return errors.New("cleanup.interval must be > 0")
	}
	if cfg.Cleanup.FlowTTL <= 0 {
		return errors.New("cleanup.flow_ttl must be > 0")
	}
	if cfg.Cleanup.SessionTTL <= 0 {
		return errors.New("cleanup.session_ttl must be > 0")
	}
	return nil
}

func validLogLevel(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "debug", "info", "warn", "error":
		return true
	default:
		return false
	}
}

func ToSlogLevel(v string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func ParseBool(value string) (bool, error) {
	v, err := strconv.ParseBool(strings.TrimSpace(value))
	if err != nil {
		return false, fmt.Errorf("expected boolean, got %q", value)
	}
	return v, nil
}
