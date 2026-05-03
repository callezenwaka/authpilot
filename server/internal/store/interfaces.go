package store

import (
	"errors"
	"time"

	"furnace/server/internal/domain"
)

var (
	ErrNotFound       = errors.New("not found")
	ErrConflict       = errors.New("already exists")
	ErrPolicyTampered = errors.New("policy content integrity check failed")
)

type UserStore interface {
	Create(user domain.User) (domain.User, error)
	GetByID(id string) (domain.User, error)
	List() ([]domain.User, error)
	Update(user domain.User) (domain.User, error)
	Delete(id string) error
}

type GroupStore interface {
	Create(group domain.Group) (domain.Group, error)
	GetByID(id string) (domain.Group, error)
	List() ([]domain.Group, error)
	Update(group domain.Group) (domain.Group, error)
	Delete(id string) error
}

type FlowStore interface {
	Create(flow domain.Flow) (domain.Flow, error)
	GetByID(id string) (domain.Flow, error)
	List() ([]domain.Flow, error)
	Update(flow domain.Flow) (domain.Flow, error)
	Delete(id string) error
	DeleteExpired(now time.Time) (int, error)
	// ConsumeAuthCode atomically finds the flow whose AuthCode matches code,
	// clears the AuthCode in storage, and returns the flow as it was before
	// clearing. Concurrent calls with the same code: exactly one succeeds.
	// Returns ErrNotFound when no flow matches or the code is empty.
	ConsumeAuthCode(code string) (domain.Flow, error)
}

type SessionStore interface {
	Create(session domain.Session) (domain.Session, error)
	GetByID(id string) (domain.Session, error)
	GetByRefreshToken(token string) (domain.Session, error)
	List() ([]domain.Session, error)
	Update(session domain.Session) (domain.Session, error)
	Delete(id string) error
	DeleteExpired(now time.Time) (int, error)
}

// APIKeyStore manages named, scoped API keys. Raw key values are never stored;
// only their SHA-256 hash is persisted. GetByHash is used by the auth middleware.
type APIKeyStore interface {
	Create(key domain.APIKey) (domain.APIKey, error)
	GetByID(id string) (domain.APIKey, error)
	GetByHash(hash string) (domain.APIKey, error)
	List() ([]domain.APIKey, error)
	Revoke(id string, at time.Time) error
	UpdateLastUsed(id string, at time.Time) error
}

// PolicyStore manages named, versioned Rego policies for the OPA Policy Admin API.
type PolicyStore interface {
	Create(policy domain.Policy) (domain.Policy, error)
	GetByID(id string) (domain.Policy, error)
	GetByName(name string) (domain.Policy, error) // returns the active version
	List() ([]domain.Policy, error)
	Activate(id string, at time.Time) error // marks one version active, deactivates others with same name
	Delete(id string) error
}

// AuditVerifyResult is returned by AuditStore.Verify.
type AuditVerifyResult struct {
	OK       bool   `json:"ok"`
	Checked  int    `json:"checked"`
	BrokenAt string `json:"broken_at,omitempty"`
	Message  string `json:"message"`
}

// AuditStore is a write-mostly append log for security-relevant events.
// Implementations may cap the log size (ring buffer); oldest entries are
// evicted first when the cap is reached.
type AuditStore interface {
	// Append records an event. Never returns an error to the caller —
	// audit failures must not block the primary operation.
	Append(event domain.AuditEvent)
	// List returns all stored events. If filter.EventType is non-empty only
	// events with that type are returned. If filter.Since is non-zero only
	// events with Timestamp >= Since are returned.
	List(filter AuditFilter) []domain.AuditEvent
	// Verify checks the tamper-evident hash chain. Returns ok=true when the
	// chain is intact. For stores without a hash chain (e.g. in-memory ring
	// buffer) Verify always returns ok=true with a descriptive message.
	Verify() (AuditVerifyResult, error)
}

// SCIMEventStore is a write-mostly log of outbound SCIM client requests.
// Like AuditStore, implementations may cap the log size.
type SCIMEventStore interface {
	Append(event domain.SCIMEvent)
	List() []domain.SCIMEvent
}

// AdminStore manages admin accounts. Completely separate from simulation users.
type AdminStore interface {
	Create(admin domain.Admin) (domain.Admin, error)
	GetByID(id string) (domain.Admin, error)
	GetByUsername(username string) (domain.Admin, error)
	List() ([]domain.Admin, error)
	Update(admin domain.Admin) (domain.Admin, error)
	Delete(id string) error
	CountActive() (int, error)
}

// AuditFilter controls which events List returns.
type AuditFilter struct {
	EventType string    // empty = all
	Since     time.Time // zero = all
}
