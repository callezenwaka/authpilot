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
