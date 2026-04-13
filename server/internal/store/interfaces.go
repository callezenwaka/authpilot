package store

import (
	"errors"
	"time"

	"authpilot/server/internal/domain"
)

var ErrNotFound = errors.New("not found")

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
}

// AuditFilter controls which events List returns.
type AuditFilter struct {
	EventType string    // empty = all
	Since     time.Time // zero = all
}
