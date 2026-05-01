package domain

import "time"

// AuditEvent records a single security-relevant action in the system.
type AuditEvent struct {
	ID         string         `json:"id"`
	Timestamp  time.Time      `json:"timestamp"`
	EventType  string         `json:"event_type"`  // e.g. "user.created", "flow.complete"
	Actor      string         `json:"actor"`        // user ID or "system"
	ResourceID string         `json:"resource_id"`  // ID of the affected resource
	Metadata   map[string]any `json:"metadata,omitempty"`
	// ChainHash is the tamper-evident hash linking this row to the previous one.
	// Never exposed via API; used only for integrity verification.
	ChainHash string `json:"-"`
}

type User struct {
	ID                  string         `json:"id"`
	Email               string         `json:"email"`
	DisplayName         string         `json:"display_name"`
	Groups              []string       `json:"groups"`
	MFAMethod           string         `json:"mfa_method"`
	NextFlow            string         `json:"next_flow"`
	Active              bool           `json:"active"`
	Claims              map[string]any `json:"claims,omitempty"`
	PhoneNumber         string         `json:"phone_number,omitempty"`
	WebAuthnCredentials string         `json:"-"` // JSON-encoded []webauthn.Credential; not exposed in API
	PasswordHash        string         `json:"-"` // argon2id PHC string or bcrypt hash; never exposed via API
	CreatedAt           time.Time      `json:"created_at"`
}

type Group struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	DisplayName string    `json:"display_name"`
	MemberIDs   []string  `json:"member_ids"`
	CreatedAt   time.Time `json:"created_at"`
}

type Flow struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	State     string    `json:"state"`
	Scenario  string    `json:"scenario,omitempty"`
	Attempts  int       `json:"attempts,omitempty"`
	Error     string    `json:"error,omitempty"`
	Protocol    string     `json:"protocol"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`

	// OIDC fields — populated when Protocol == "oidc"
	ClientID      string   `json:"client_id,omitempty"`
	RedirectURI   string   `json:"redirect_uri,omitempty"`
	Scopes        []string `json:"scopes,omitempty"`
	ResponseType  string   `json:"response_type,omitempty"`
	OAuthState    string   `json:"oauth_state,omitempty"`
	Nonce         string   `json:"nonce,omitempty"`
	PKCEChallenge string   `json:"pkce_challenge,omitempty"`
	PKCEMethod    string   `json:"pkce_method,omitempty"`
	AuthCode      string   `json:"-"` // not exposed; redeemed once at /token

	// Notification fields — ephemeral, populated when MFA is pending
	TOTPSecret        string `json:"-"`                           // base32 TOTP secret for this flow
	SMSCode           string `json:"-"`                           // 6-digit code for SMS method
	MagicLinkToken    string `json:"-"`                           // opaque token for magic link
	MagicLinkUsed     bool   `json:"magic_link_used,omitempty"`
	WebAuthnChallenge string `json:"webauthn_challenge,omitempty"` // base64url challenge (kept for notify hub display)
	WebAuthnSession   string `json:"-"`                           // JSON-encoded webauthn.SessionData between begin and finish
}

type SessionEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"`
	Details   string    `json:"details,omitempty"`
}

// SCIMEvent records a single outbound SCIM request made when Furnace runs
// in client mode (FURNACE_SCIM_MODE=client).
type SCIMEvent struct {
	ID             string    `json:"id"`
	Timestamp      time.Time `json:"timestamp"`
	Method         string    `json:"method"`
	URL            string    `json:"url"`
	RequestBody    string    `json:"request_body,omitempty"`
	ResponseStatus int       `json:"response_status"`
	ResponseBody   string    `json:"response_body,omitempty"`
	Error          string    `json:"error,omitempty"` // set when the HTTP request itself failed
}

// APIKey is a named, scoped credential stored in the key store.
// The raw key value is returned only on creation and never stored.
// KeyHash (SHA-256 of the raw key) is used for all subsequent lookups.
type APIKey struct {
	ID         string     `json:"id"`
	Label      string     `json:"label"`
	KeyHash    string     `json:"-"`
	Scopes     []string   `json:"scopes"`
	CreatedAt  time.Time  `json:"created_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// Policy is a named, versioned Rego policy stored in the policy admin store.
type Policy struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Version     string     `json:"version"`
	Content     string     `json:"content"`
	ContentHash string     `json:"content_hash"`
	Active      bool       `json:"active"`
	CreatedAt   time.Time  `json:"created_at"`
	ActivatedAt *time.Time `json:"activated_at,omitempty"`
	// Signature is an ed25519 signature of ContentHash computed at activation time.
	// Never exposed via API; used internally to detect DB-level tampering.
	Signature string `json:"-"`
}

type Session struct {
	ID           string         `json:"id"`
	UserID       string         `json:"user_id"`
	FlowID       string         `json:"flow_id"`
	Protocol     string         `json:"protocol,omitempty"`
	Provider     string         `json:"provider,omitempty"`
	ClientID     string         `json:"client_id,omitempty"`
	Events       []SessionEvent `json:"events,omitempty"`
	RefreshToken string         `json:"-"` // opaque; not exposed in API responses
	CreatedAt    time.Time      `json:"created_at"`
	ExpiresAt    time.Time      `json:"expires_at"`
}
