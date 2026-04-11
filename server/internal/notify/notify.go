// Package notify generates ephemeral MFA credentials for flows and
// builds the notification payloads returned by GET /api/v1/notifications.
package notify

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/pquerna/otp/totp"

	"authpilot/server/internal/domain"
)

// Payload is returned by the notifications endpoint for a given flow.
type Payload struct {
	FlowID    string `json:"flow_id"`
	Type      string `json:"type"` // "totp" | "push" | "sms" | "magic_link" | "none"
	UserID    string `json:"user_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`

	// TOTP
	TOTPCode      string `json:"totp_code,omitempty"`
	TOTPExpiresAt string `json:"totp_expires_at,omitempty"`

	// SMS
	SMSCode   string `json:"sms_code,omitempty"`
	SMSTarget string `json:"sms_target,omitempty"` // masked phone number

	// Push
	PushPending bool `json:"push_pending,omitempty"`

	// Magic link
	MagicLinkURL  string `json:"magic_link_url,omitempty"`
	MagicLinkUsed bool   `json:"magic_link_used,omitempty"`
}

// EnsureSecrets populates the notification secrets on a flow if they are not
// already set. Returns the (possibly updated) flow and whether it changed.
func EnsureSecrets(flow domain.Flow) (domain.Flow, bool, error) {
	if flow.State != "mfa_pending" {
		return flow, false, nil
	}
	changed := false

	switch flow.Scenario {
	// account_locked and error states never reach mfa_pending, so no special case needed.
	}

	// We don't know the MFA method here — the caller must supply user info.
	// Secrets are generated lazily by GenerateFor.
	return flow, changed, nil
}

// GenerateFor builds a Payload for the given flow and user, generating
// ephemeral secrets on the flow when they are missing.
// Returns the payload and the (possibly updated) flow.
func GenerateFor(flow domain.Flow, user domain.User, baseURL string) (Payload, domain.Flow, error) {
	p := Payload{
		FlowID:    flow.ID,
		UserID:    user.ID,
		UserEmail: user.Email,
	}

	if flow.State != "mfa_pending" {
		p.Type = "none"
		return p, flow, nil
	}

	changed := false

	switch user.MFAMethod {
	case "totp":
		p.Type = "totp"
		if flow.TOTPSecret == "" {
			secret, err := generateTOTPSecret()
			if err != nil {
				return Payload{}, flow, fmt.Errorf("generate totp secret: %w", err)
			}
			flow.TOTPSecret = secret
			changed = true
		}
		code, expiresAt, err := currentTOTPCode(flow.TOTPSecret)
		if err != nil {
			return Payload{}, flow, fmt.Errorf("generate totp code: %w", err)
		}
		p.TOTPCode = code
		p.TOTPExpiresAt = expiresAt
		_ = changed

	case "sms":
		p.Type = "sms"
		if flow.SMSCode == "" {
			code, err := generateSMSCode()
			if err != nil {
				return Payload{}, flow, fmt.Errorf("generate sms code: %w", err)
			}
			flow.SMSCode = code
			changed = true
		}
		p.SMSCode = flow.SMSCode
		p.SMSTarget = maskPhone(user.PhoneNumber)

	case "push":
		p.Type = "push"
		p.PushPending = true

	case "magic_link":
		p.Type = "magic_link"
		if flow.MagicLinkToken == "" {
			token, err := generateToken(24)
			if err != nil {
				return Payload{}, flow, fmt.Errorf("generate magic link token: %w", err)
			}
			flow.MagicLinkToken = token
			changed = true
		}
		p.MagicLinkURL = baseURL + "/login/magic?token=" + flow.MagicLinkToken
		p.MagicLinkUsed = flow.MagicLinkUsed

	default:
		p.Type = "none"
	}

	return p, flow, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func generateTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.EncodeToString(b), nil
}

func currentTOTPCode(secret string) (string, string, error) {
	now := time.Now()
	code, err := totp.GenerateCode(secret, now)
	if err != nil {
		return "", "", err
	}
	// TOTP period is 30s; compute when the current window expires.
	windowEnd := time.Unix((now.Unix()/30+1)*30, 0).UTC()
	return code, windowEnd.Format(time.RFC3339), nil
}

func generateSMSCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func generateToken(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func maskPhone(phone string) string {
	if len(phone) < 4 {
		return "••• ••••"
	}
	return "••• " + phone[len(phone)-4:]
}
