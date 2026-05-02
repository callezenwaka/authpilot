package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// TenancyMode controls single vs. multi-tenant operation.
type TenancyMode string

const (
	TenancySingle TenancyMode = "single"
	TenancyMulti  TenancyMode = "multi"
)

// TenantConfig defines one tenant in multi-tenant mode.
type TenantConfig struct {
	ID            string `yaml:"id"`
	APIKey        string `json:"-" yaml:"api_key"`
	SCIMKey       string `json:"-" yaml:"scim_key"` // optional; falls back to APIKey
	OIDCIssuerURL string `yaml:"oidc_issuer_url"`   // optional; overrides global OIDC issuer
}

// MarshalYAML redacts the API key and SCIM key fields when a TenantConfig is
// emitted to YAML (debug dumps, status endpoints). The struct is still loaded
// from YAML normally — Unmarshal does not invoke MarshalYAML — so multi-tenant
// configuration keeps working. Empty fields stay empty so unset values don't
// look like redacted secrets.
func (t TenantConfig) MarshalYAML() (interface{}, error) {
	redact := func(v string) string {
		if v == "" {
			return ""
		}
		return "<redacted>"
	}
	return struct {
		ID            string `yaml:"id"`
		APIKey        string `yaml:"api_key"`
		SCIMKey       string `yaml:"scim_key,omitempty"`
		OIDCIssuerURL string `yaml:"oidc_issuer_url,omitempty"`
	}{
		ID:            t.ID,
		APIKey:        redact(t.APIKey),
		SCIMKey:       redact(t.SCIMKey),
		OIDCIssuerURL: t.OIDCIssuerURL,
	}, nil
}

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
	WebAuthn     WebAuthnConfig    `yaml:"webauthn"`
	APIKey            string        `json:"-" yaml:"-"`         // FURNACE_API_KEY; required in single-tenant mode (per-tenant keys in tenants[] in multi-tenant mode)
	SCIMKey           string        `json:"-" yaml:"-"`         // FURNACE_SCIM_KEY; separate credential for /scim/v2; falls back to APIKey when empty
	SessionHashKey    []byte        `json:"-" yaml:"-"`         // FURNACE_SESSION_HASH_KEY (base64, 32+ bytes); required; HMAC key for at-rest hashing of refresh tokens
	AuthEventLog      string        `json:"-" yaml:"-"`         // FURNACE_AUTH_EVENT_LOG; "" or "stderr" = stderr; file path = append to that file
	RateLimit         int           `yaml:"rate_limit"`         // requests/min per IP on /api/v1; 0 = disabled
	CORSOrigins       []string      `yaml:"cors_origins"`       // FURNACE_CORS_ORIGINS; allowed origins for protocol server; empty = "*"
	TrustedProxyCIDRs []string      `yaml:"trusted_proxy_cidrs"` // FURNACE_TRUSTED_PROXY_CIDRS; X-Forwarded-For honoured only when RemoteAddr is in one of these CIDRs; empty = XFF ignored
	SeedUsers         []SeedUser    `yaml:"seed_users"`         // users created at startup; idempotent
	HeaderPropagation bool                 `yaml:"header_propagation"`  // inject X-User-* headers on /userinfo responses
	HeaderMappings    []HeaderMappingConfig `yaml:"header_mappings"`     // custom header→claim mappings; overrides default X-User-* when non-empty
	Tokens            TokensConfig          `yaml:"tokens"`              // token format flags and framework claim configs
	OPA               OPAConfig             `yaml:"opa"`                 // embedded OPA engine settings
	Tenancy           TenancyMode           `yaml:"tenancy"`             // "single" (default) or "multi"
	Tenants           []TenantConfig `yaml:"tenants"`            // populated only in multi mode
	Provider          string         `yaml:"provider"`           // personality ID: "default", "okta", "azure-ad", etc.
	SCIMClientMode    bool           `yaml:"scim_client_mode"`   // true when FURNACE_SCIM_MODE=client
	SCIMTargetURL     string         `yaml:"scim_target_url"`    // FURNACE_SCIM_TARGET; required when SCIMClientMode=true
}

// WebAuthnConfig pins the relying-party identifiers used by all WebAuthn
// endpoints. Both fields are required when WebAuthn is in use; the request
// Host header is verified against Origin so a spoofable Host cannot break
// credential origin binding.
type WebAuthnConfig struct {
	RPID   string `yaml:"rp_id"`  // FURNACE_WEBAUTHN_RP_ID; e.g. "app.furnace.io"
	Origin string `yaml:"origin"` // FURNACE_WEBAUTHN_ORIGIN; e.g. "https://app.furnace.io"
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
	// KeyRotationInterval is how often the OIDC signing key is rotated.
	// 0 (default) disables automatic rotation. Set via FURNACE_KEY_ROTATION_INTERVAL.
	KeyRotationInterval time.Duration `yaml:"key_rotation_interval"`
	// KeyRotationOverlap is how long a retired key stays published in JWKS
	// after rotation, giving downstream JWKS caches time to refresh.
	// Defaults to 24h. Set via FURNACE_KEY_ROTATION_OVERLAP.
	KeyRotationOverlap time.Duration `yaml:"key_rotation_overlap"`
}

// OPA default limits
const (
	OPADefaultCompileTimeout = 2 * time.Second
	OPADefaultEvalTimeout    = 5 * time.Second
	OPADefaultMaxPolicyBytes = int64(64 * 1024)       // 64 KiB
	OPADefaultMaxDataBytes   = int64(5 * 1024 * 1024) // 5 MiB
	OPADefaultMaxBatchChecks = 100
)

// OPATenantDecisionLog provides per-tenant overrides for the OPA decision log.
// All settings can only tighten global behaviour — they cannot disable global
// redaction, restore scrubbed fields, or extend retention beyond the global limit.
// Configured via YAML only; there is no env-var representation for this nested map.
type OPATenantDecisionLog struct {
	// AdditionalRedactFields is merged with the global redact_fields list.
	// Paths use dot notation, e.g. "user.claims.ssn".
	AdditionalRedactFields []string `yaml:"additional_redact_fields"`
	// ScrubPolicyCredentials enables credential scrubbing for this tenant even
	// when the global setting is false. Has no effect when global is already true.
	ScrubPolicyCredentials bool `yaml:"scrub_policy_credentials"`
	// RetentionDays overrides global retention for log entries belonging to this
	// tenant. When > 0 and tighter than the global value, per-tenant entries are
	// pruned earlier. 0 means "inherit global".
	RetentionDays int `yaml:"retention_days"`
}

// OPATenantBudget defines per-tenant OPA resource limits.
// All fields are optional (zero = use global default).
// Per-tenant budgets can only be equal to or tighter than the global limits —
// the engine takes min(global, per-tenant) for each field so a misconfigured
// override cannot loosen protection. Configurable via YAML only; there is no
// env-var representation for this nested map.
type OPATenantBudget struct {
	EvalTimeout    time.Duration         `yaml:"eval_timeout"`
	CompileTimeout time.Duration         `yaml:"compile_timeout"`
	MaxPolicyBytes int64                 `yaml:"max_policy_bytes"`
	MaxDataBytes   int64                 `yaml:"max_data_bytes"`
	MaxBatchChecks int                   `yaml:"max_batch_checks"`
	DecisionLog    *OPATenantDecisionLog `yaml:"decision_log"`
}

// OPAConfig holds all OPA integration settings.
type OPAConfig struct {
	CompileTimeout  time.Duration              `yaml:"compile_timeout"`   // default 2s
	EvalTimeout     time.Duration              `yaml:"eval_timeout"`      // default 5s
	MaxPolicyBytes  int64                      `yaml:"max_policy_bytes"`  // default 64 KiB
	MaxDataBytes    int64                      `yaml:"max_data_bytes"`    // default 5 MiB
	MaxBatchChecks  int                        `yaml:"max_batch_checks"`  // default 100
	MaxConcurrent   int                        `yaml:"max_concurrent"`    // semaphore size; default runtime.NumCPU()
	DecisionLog     OPADecisionLogConfig       `yaml:"decision_log"`
	TenantBudgets   map[string]OPATenantBudget `yaml:"tenant_budgets"`    // per-tenant overrides; only tighter than global
}

// OPADecisionLogConfig controls what the OPA decision log records.
type OPADecisionLogConfig struct {
	Enabled       bool   `yaml:"enabled"`        // default true
	IncludeInput  bool   `yaml:"include_input"`  // default false — opt-in to avoid PII leaks in shared deployments
	IncludePolicy bool   `yaml:"include_policy"` // default false — policy text can be large
	Destination   string `yaml:"destination"`    // "stdout" (default) | "stderr" | file path

	// PII and credential controls.
	// RedactFields is a list of dot-separated paths in Input to replace with "[REDACTED]"
	// before writing the log entry. e.g. ["user.claims.email", "user.claims.ssn"].
	RedactFields []string `yaml:"redact_fields"`
	// ScrubPolicyCredentials removes patterns that look like credentials (bearer tokens,
	// base64 secrets, password assignments) from the policy text before logging.
	// Only applies when include_policy is true.
	ScrubPolicyCredentials bool `yaml:"scrub_policy_credentials"`

	// Retention. RetentionDays > 0 enables startup pruning of log entries older than
	// N days. Only applies when Destination is a file path.
	RetentionDays int `yaml:"retention_days"`
}

// TokenFormatConfig controls optional JWT claim fields for API gateway compatibility.
type TokenFormatConfig struct {
	IncludeJTI   bool `yaml:"include_jti"`   // add jti (unique token ID) to every token
	AudAsArray   bool `yaml:"aud_as_array"`  // emit aud as ["clientID"] instead of "clientID"
	IncludeScope bool `yaml:"include_scope"` // add scope claim to access token
}

// HasuraClaimsConfig injects a Hasura-compatible claim namespace into the ID token.
type HasuraClaimsConfig struct {
	Enabled      bool     `yaml:"enabled"`
	Namespace    string   `yaml:"namespace"`     // defaults to "https://hasura.io/jwt/claims"
	DefaultRole  string   `yaml:"default_role"`
	AllowedRoles []string `yaml:"allowed_roles"` // defaults to user groups when empty
}

// ApolloClaimsConfig declares which JWT claims Apollo Federation resolvers should read.
// This is a routing hint only — no token changes are made.
type ApolloClaimsConfig struct {
	Enabled     bool   `yaml:"enabled"`
	UserIDClaim string `yaml:"user_id_claim"` // defaults to "sub"
	RolesClaim  string `yaml:"roles_claim"`   // defaults to "groups"
}

// TokensConfig groups token-format and framework-integration options.
type TokensConfig struct {
	Format       TokenFormatConfig  `yaml:"format"`
	HasuraClaims HasuraClaimsConfig `yaml:"hasura_claims"`
	ApolloClaims ApolloClaimsConfig `yaml:"apollo_claims"`
}

// HeaderMappingConfig declares one response header injected on /userinfo when
// header_propagation is enabled and header_mappings is non-empty.
type HeaderMappingConfig struct {
	Name  string `yaml:"name"`  // HTTP header name, e.g. "X-User-Email"
	Claim string `yaml:"claim"` // userinfo claim key, e.g. "email"
	Join  string `yaml:"join"`  // separator for array claims; defaults to ","
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
			Enabled:    true,
			SQLitePath: "./data/furnace.db",
		},
		Cleanup: CleanupConfig{
			Interval:   60 * time.Second,
			FlowTTL:    30 * time.Minute,
			SessionTTL: 12 * time.Hour,
		},
		OIDC: OIDCConfig{
			IssuerURL:          "http://localhost:8026",
			AccessTokenTTL:     1 * time.Hour,
			IDTokenTTL:         1 * time.Hour,
			RefreshTokenTTL:    30 * 24 * time.Hour,
			KeyRotationOverlap: 24 * time.Hour,
		},
		SAML: SAMLConfig{
			EntityID: "http://localhost:8026",
		},
		OPA: OPAConfig{
			CompileTimeout: OPADefaultCompileTimeout,
			EvalTimeout:    OPADefaultEvalTimeout,
			MaxPolicyBytes: OPADefaultMaxPolicyBytes,
			MaxDataBytes:   OPADefaultMaxDataBytes,
			MaxBatchChecks: OPADefaultMaxBatchChecks,
			DecisionLog: OPADecisionLogConfig{
				Enabled:     true,
				Destination: "stdout",
			},
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
	WebAuthn     WebAuthnConfig       `yaml:"webauthn"`
	SeedUsers    []SeedUser           `yaml:"seed_users"`
	Tenancy        string               `yaml:"tenancy"`
	Tenants        []TenantConfig       `yaml:"tenants"`
	Provider       string               `yaml:"provider"`
	SCIMClientMode bool                 `yaml:"scim_client_mode"`
	SCIMTargetURL  string               `yaml:"scim_target_url"`
	Tokens         TokensConfig         `yaml:"tokens"`
	HeaderMappings []HeaderMappingConfig `yaml:"header_mappings"`
	OPA            OPAConfig            `yaml:"opa"`
}

type yamlOIDC struct {
	IssuerURL           string `yaml:"issuer_url"`
	AccessTokenTTL      string `yaml:"access_token_ttl"`
	IDTokenTTL          string `yaml:"id_token_ttl"`
	RefreshTokenTTL     string `yaml:"refresh_token_ttl"`
	KeyRotationInterval string `yaml:"key_rotation_interval"`
	KeyRotationOverlap  string `yaml:"key_rotation_overlap"`
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
	if from.OIDC.KeyRotationInterval != "" {
		d, err := time.ParseDuration(from.OIDC.KeyRotationInterval)
		if err != nil || d < 0 {
			return fmt.Errorf("yaml oidc.key_rotation_interval: must be a valid non-negative duration")
		}
		cfg.OIDC.KeyRotationInterval = d
	}
	if from.OIDC.KeyRotationOverlap != "" {
		d, err := time.ParseDuration(from.OIDC.KeyRotationOverlap)
		if err != nil || d < 0 {
			return fmt.Errorf("yaml oidc.key_rotation_overlap: must be a valid non-negative duration")
		}
		cfg.OIDC.KeyRotationOverlap = d
	}
	if from.WebAuthn.RPID != "" {
		cfg.WebAuthn.RPID = from.WebAuthn.RPID
	}
	if from.WebAuthn.Origin != "" {
		cfg.WebAuthn.Origin = from.WebAuthn.Origin
	}
	if len(from.SeedUsers) > 0 {
		cfg.SeedUsers = append(cfg.SeedUsers, from.SeedUsers...)
	}
	if from.Tenancy != "" {
		cfg.Tenancy = TenancyMode(from.Tenancy)
	}
	if len(from.Tenants) > 0 {
		cfg.Tenants = from.Tenants
	}
	if from.Provider != "" {
		cfg.Provider = from.Provider
	}
	if from.SCIMClientMode {
		cfg.SCIMClientMode = true
	}
	if from.SCIMTargetURL != "" {
		cfg.SCIMTargetURL = from.SCIMTargetURL
	}
	if from.Tokens.Format.IncludeJTI {
		cfg.Tokens.Format.IncludeJTI = true
	}
	if from.Tokens.Format.AudAsArray {
		cfg.Tokens.Format.AudAsArray = true
	}
	if from.Tokens.Format.IncludeScope {
		cfg.Tokens.Format.IncludeScope = true
	}
	if from.Tokens.HasuraClaims.Enabled {
		cfg.Tokens.HasuraClaims = from.Tokens.HasuraClaims
	}
	if from.Tokens.ApolloClaims.Enabled {
		cfg.Tokens.ApolloClaims = from.Tokens.ApolloClaims
	}
	if len(from.HeaderMappings) > 0 {
		cfg.HeaderMappings = from.HeaderMappings
	}
	if from.OPA.CompileTimeout > 0 {
		cfg.OPA.CompileTimeout = from.OPA.CompileTimeout
	}
	if from.OPA.EvalTimeout > 0 {
		cfg.OPA.EvalTimeout = from.OPA.EvalTimeout
	}
	if from.OPA.MaxPolicyBytes > 0 {
		cfg.OPA.MaxPolicyBytes = from.OPA.MaxPolicyBytes
	}
	if from.OPA.MaxDataBytes > 0 {
		cfg.OPA.MaxDataBytes = from.OPA.MaxDataBytes
	}
	if from.OPA.MaxBatchChecks > 0 {
		cfg.OPA.MaxBatchChecks = from.OPA.MaxBatchChecks
	}
	if from.OPA.MaxConcurrent > 0 {
		cfg.OPA.MaxConcurrent = from.OPA.MaxConcurrent
	}
	if from.OPA.DecisionLog.Destination != "" || from.OPA.DecisionLog.RetentionDays > 0 || len(from.OPA.DecisionLog.RedactFields) > 0 || from.OPA.DecisionLog.ScrubPolicyCredentials {
		cfg.OPA.DecisionLog = from.OPA.DecisionLog
	}
	if len(from.OPA.TenantBudgets) > 0 {
		cfg.OPA.TenantBudgets = from.OPA.TenantBudgets
	}
	return nil
}

func applyEnv(cfg *Config) error {
	if v := strings.TrimSpace(os.Getenv("FURNACE_HTTP_ADDR")); v != "" {
		cfg.HTTPAddr = v
	}
	if v := strings.TrimSpace(os.Getenv("FURNACE_PROTOCOL_ADDR")); v != "" {
		cfg.ProtocolAddr = v
	}
	if v := strings.TrimSpace(os.Getenv("FURNACE_LOG_LEVEL")); v != "" {
		cfg.LogLevel = v
	}
	if v := strings.TrimSpace(os.Getenv("FURNACE_PERSISTENCE_ENABLED")); v != "" {
		b, err := ParseBool(v)
		if err != nil {
			return fmt.Errorf("FURNACE_PERSISTENCE_ENABLED: %w", err)
		}
		cfg.Persistence.Enabled = b
	}
	if v := strings.TrimSpace(os.Getenv("FURNACE_SQLITE_PATH")); v != "" {
		cfg.Persistence.SQLitePath = v
	}
	if v := strings.TrimSpace(os.Getenv("FURNACE_CLEANUP_INTERVAL")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("FURNACE_CLEANUP_INTERVAL: %w", err)
		}
		cfg.Cleanup.Interval = d
	}
	if v := strings.TrimSpace(os.Getenv("FURNACE_FLOW_TTL")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("FURNACE_FLOW_TTL: %w", err)
		}
		cfg.Cleanup.FlowTTL = d
	}
	if v := strings.TrimSpace(os.Getenv("FURNACE_SESSION_TTL")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("FURNACE_SESSION_TTL: %w", err)
		}
		cfg.Cleanup.SessionTTL = d
	}
	if v := strings.TrimSpace(os.Getenv("FURNACE_OIDC_ISSUER_URL")); v != "" {
		cfg.OIDC.IssuerURL = v
	}
	if v := strings.TrimSpace(os.Getenv("FURNACE_KEY_ROTATION_INTERVAL")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 0 {
			return fmt.Errorf("FURNACE_KEY_ROTATION_INTERVAL: must be a valid non-negative duration (e.g. 24h)")
		}
		cfg.OIDC.KeyRotationInterval = d
	}
	if v := strings.TrimSpace(os.Getenv("FURNACE_KEY_ROTATION_OVERLAP")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 0 {
			return fmt.Errorf("FURNACE_KEY_ROTATION_OVERLAP: must be a valid non-negative duration (e.g. 24h)")
		}
		cfg.OIDC.KeyRotationOverlap = d
	}
	if v := strings.TrimSpace(os.Getenv("FURNACE_API_KEY")); v != "" {
		cfg.APIKey = v
	}
	if v := strings.TrimSpace(os.Getenv("FURNACE_SCIM_KEY")); v != "" {
		cfg.SCIMKey = v
	}
	if v := strings.TrimSpace(os.Getenv("FURNACE_AUTH_EVENT_LOG")); v != "" {
		cfg.AuthEventLog = v
	}
	if v := strings.TrimSpace(os.Getenv("FURNACE_SESSION_HASH_KEY")); v != "" {
		decoded, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return fmt.Errorf("FURNACE_SESSION_HASH_KEY: not valid base64: %w", err)
		}
		if len(decoded) < 16 {
			return fmt.Errorf("FURNACE_SESSION_HASH_KEY: too short (%d bytes); minimum 16, recommended 32", len(decoded))
		}
		cfg.SessionHashKey = decoded
	}
	if v := strings.TrimSpace(os.Getenv("FURNACE_CORS_ORIGINS")); v != "" {
		for _, o := range strings.Split(v, ",") {
			if o = strings.TrimSpace(o); o != "" {
				cfg.CORSOrigins = append(cfg.CORSOrigins, o)
			}
		}
	}
	if v := strings.TrimSpace(os.Getenv("FURNACE_TRUSTED_PROXY_CIDRS")); v != "" {
		for _, c := range strings.Split(v, ",") {
			if c = strings.TrimSpace(c); c != "" {
				cfg.TrustedProxyCIDRs = append(cfg.TrustedProxyCIDRs, c)
			}
		}
	}
	if v := strings.TrimSpace(os.Getenv("FURNACE_RATE_LIMIT")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("FURNACE_RATE_LIMIT: %w", err)
		}
		cfg.RateLimit = n
	}
	if v := strings.TrimSpace(os.Getenv("FURNACE_SAML_ENTITY_ID")); v != "" {
		cfg.SAML.EntityID = v
	}
	if v := strings.TrimSpace(os.Getenv("FURNACE_SAML_CERT_DIR")); v != "" {
		cfg.SAML.CertDir = v
	}
	if v := strings.TrimSpace(os.Getenv("FURNACE_WEBAUTHN_RP_ID")); v != "" {
		cfg.WebAuthn.RPID = v
	}
	if v := strings.TrimSpace(os.Getenv("FURNACE_WEBAUTHN_ORIGIN")); v != "" {
		cfg.WebAuthn.Origin = v
	}
	if v := strings.TrimSpace(os.Getenv("FURNACE_HEADER_PROPAGATION")); v != "" {
		b, err := ParseBool(v)
		if err != nil {
			return fmt.Errorf("FURNACE_HEADER_PROPAGATION: %w", err)
		}
		cfg.HeaderPropagation = b
	}
	if v := strings.TrimSpace(os.Getenv("FURNACE_TENANCY")); v != "" {
		cfg.Tenancy = TenancyMode(v)
	}
	if v := strings.TrimSpace(os.Getenv("FURNACE_PROVIDER")); v != "" {
		cfg.Provider = v
	}
	if strings.ToLower(strings.TrimSpace(os.Getenv("FURNACE_SCIM_MODE"))) == "client" {
		cfg.SCIMClientMode = true
	}
	if v := strings.TrimSpace(os.Getenv("FURNACE_SCIM_TARGET")); v != "" {
		cfg.SCIMTargetURL = v
	}
	if v := strings.TrimSpace(os.Getenv("FURNACE_SEED_USERS")); v != "" {
		var users []SeedUser
		if err := yaml.Unmarshal([]byte(v), &users); err != nil {
			return fmt.Errorf("FURNACE_SEED_USERS: %w", err)
		}
		cfg.SeedUsers = append(cfg.SeedUsers, users...)
	}
	if v := strings.TrimSpace(os.Getenv("FURNACE_OPA_DECISION_LOG_REDACT_FIELDS")); v != "" {
		for _, f := range strings.Split(v, ",") {
			if f = strings.TrimSpace(f); f != "" {
				cfg.OPA.DecisionLog.RedactFields = append(cfg.OPA.DecisionLog.RedactFields, f)
			}
		}
	}
	if v := strings.TrimSpace(os.Getenv("FURNACE_OPA_DECISION_LOG_SCRUB_CREDENTIALS")); v != "" {
		b, err := ParseBool(v)
		if err != nil {
			return fmt.Errorf("FURNACE_OPA_DECISION_LOG_SCRUB_CREDENTIALS: %w", err)
		}
		cfg.OPA.DecisionLog.ScrubPolicyCredentials = b
	}
	if v := strings.TrimSpace(os.Getenv("FURNACE_OPA_DECISION_LOG_RETENTION_DAYS")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return fmt.Errorf("FURNACE_OPA_DECISION_LOG_RETENTION_DAYS: must be a non-negative integer")
		}
		cfg.OPA.DecisionLog.RetentionDays = n
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
	switch cfg.Tenancy {
	case "", TenancySingle, TenancyMulti:
		// valid
	default:
		return fmt.Errorf("tenancy must be %q or %q, got %q", TenancySingle, TenancyMulti, cfg.Tenancy)
	}
	if cfg.SCIMClientMode && strings.TrimSpace(cfg.SCIMTargetURL) == "" {
		return errors.New("scim_target_url (FURNACE_SCIM_TARGET) is required when scim_client_mode is enabled")
	}
	if cfg.Tenancy == TenancyMulti {
		if len(cfg.Tenants) == 0 {
			return errors.New("tenancy: multi requires at least one tenant defined in tenants[]")
		}
		seen := make(map[string]bool, len(cfg.Tenants))
		for i, t := range cfg.Tenants {
			if t.ID == "" {
				return fmt.Errorf("tenants[%d].id must not be empty", i)
			}
			if t.APIKey == "" {
				return fmt.Errorf("tenants[%d].api_key must not be empty", i)
			}
			if seen[t.ID] {
				return fmt.Errorf("tenants[%d].id %q is duplicated", i, t.ID)
			}
			seen[t.ID] = true
		}
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
