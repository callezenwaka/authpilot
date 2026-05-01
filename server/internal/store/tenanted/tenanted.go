// Package tenanted provides store wrappers that scope all operations to a
// fixed tenant ID using an internal ID prefix (tenantID::originalID).
// The prefix is an implementation detail — callers always see the original IDs.
package tenanted

import (
	"context"
	"strings"
	"time"

	"furnace/server/internal/domain"
	"furnace/server/internal/store"
	"furnace/server/internal/tenant"
)

const sep = "::"

func addPrefix(tenantID, id string) string  { return tenantID + sep + id }
func hasPrefix(tenantID, id string) bool    { return strings.HasPrefix(id, tenantID+sep) }
func stripPrefix(tenantID, id string) string {
	return strings.TrimPrefix(id, tenantID+sep)
}

// ---- UserStore ----

type UserStore struct {
	inner    store.UserStore
	tenantID string
}

func NewUserStore(inner store.UserStore, tenantID string) *UserStore {
	return &UserStore{inner: inner, tenantID: tenantID}
}

func (s *UserStore) Create(u domain.User) (domain.User, error) {
	u.ID = addPrefix(s.tenantID, u.ID)
	created, err := s.inner.Create(u)
	if err != nil {
		return domain.User{}, err
	}
	created.ID = stripPrefix(s.tenantID, created.ID)
	return created, nil
}

func (s *UserStore) GetByID(id string) (domain.User, error) {
	u, err := s.inner.GetByID(addPrefix(s.tenantID, id))
	if err != nil {
		return domain.User{}, err
	}
	u.ID = stripPrefix(s.tenantID, u.ID)
	return u, nil
}

func (s *UserStore) List() ([]domain.User, error) {
	all, err := s.inner.List()
	if err != nil {
		return nil, err
	}
	var out []domain.User
	for _, u := range all {
		if hasPrefix(s.tenantID, u.ID) {
			u.ID = stripPrefix(s.tenantID, u.ID)
			out = append(out, u)
		}
	}
	return out, nil
}

func (s *UserStore) Update(u domain.User) (domain.User, error) {
	u.ID = addPrefix(s.tenantID, u.ID)
	updated, err := s.inner.Update(u)
	if err != nil {
		return domain.User{}, err
	}
	updated.ID = stripPrefix(s.tenantID, updated.ID)
	return updated, nil
}

func (s *UserStore) Delete(id string) error {
	return s.inner.Delete(addPrefix(s.tenantID, id))
}

// ---- GroupStore ----

type GroupStore struct {
	inner    store.GroupStore
	tenantID string
}

func NewGroupStore(inner store.GroupStore, tenantID string) *GroupStore {
	return &GroupStore{inner: inner, tenantID: tenantID}
}

func (s *GroupStore) Create(g domain.Group) (domain.Group, error) {
	g.ID = addPrefix(s.tenantID, g.ID)
	created, err := s.inner.Create(g)
	if err != nil {
		return domain.Group{}, err
	}
	created.ID = stripPrefix(s.tenantID, created.ID)
	return created, nil
}

func (s *GroupStore) GetByID(id string) (domain.Group, error) {
	g, err := s.inner.GetByID(addPrefix(s.tenantID, id))
	if err != nil {
		return domain.Group{}, err
	}
	g.ID = stripPrefix(s.tenantID, g.ID)
	return g, nil
}

func (s *GroupStore) List() ([]domain.Group, error) {
	all, err := s.inner.List()
	if err != nil {
		return nil, err
	}
	var out []domain.Group
	for _, g := range all {
		if hasPrefix(s.tenantID, g.ID) {
			g.ID = stripPrefix(s.tenantID, g.ID)
			out = append(out, g)
		}
	}
	return out, nil
}

func (s *GroupStore) Update(g domain.Group) (domain.Group, error) {
	g.ID = addPrefix(s.tenantID, g.ID)
	updated, err := s.inner.Update(g)
	if err != nil {
		return domain.Group{}, err
	}
	updated.ID = stripPrefix(s.tenantID, updated.ID)
	return updated, nil
}

func (s *GroupStore) Delete(id string) error {
	return s.inner.Delete(addPrefix(s.tenantID, id))
}

// ---- FlowStore ----

type FlowStore struct {
	inner    store.FlowStore
	tenantID string
}

func NewFlowStore(inner store.FlowStore, tenantID string) *FlowStore {
	return &FlowStore{inner: inner, tenantID: tenantID}
}

func (s *FlowStore) Create(f domain.Flow) (domain.Flow, error) {
	f.ID = addPrefix(s.tenantID, f.ID)
	created, err := s.inner.Create(f)
	if err != nil {
		return domain.Flow{}, err
	}
	created.ID = stripPrefix(s.tenantID, created.ID)
	return created, nil
}

func (s *FlowStore) GetByID(id string) (domain.Flow, error) {
	f, err := s.inner.GetByID(addPrefix(s.tenantID, id))
	if err != nil {
		return domain.Flow{}, err
	}
	f.ID = stripPrefix(s.tenantID, f.ID)
	return f, nil
}

func (s *FlowStore) List() ([]domain.Flow, error) {
	all, err := s.inner.List()
	if err != nil {
		return nil, err
	}
	var out []domain.Flow
	for _, f := range all {
		if hasPrefix(s.tenantID, f.ID) {
			f.ID = stripPrefix(s.tenantID, f.ID)
			out = append(out, f)
		}
	}
	return out, nil
}

func (s *FlowStore) Update(f domain.Flow) (domain.Flow, error) {
	f.ID = addPrefix(s.tenantID, f.ID)
	updated, err := s.inner.Update(f)
	if err != nil {
		return domain.Flow{}, err
	}
	updated.ID = stripPrefix(s.tenantID, updated.ID)
	return updated, nil
}

func (s *FlowStore) Delete(id string) error {
	return s.inner.Delete(addPrefix(s.tenantID, id))
}

func (s *FlowStore) ConsumeAuthCode(code string) (domain.Flow, error) {
	f, err := s.inner.ConsumeAuthCode(code)
	if err != nil {
		return domain.Flow{}, err
	}
	if !hasPrefix(s.tenantID, f.ID) {
		// auth-code collision across tenants (negligible with cryptographic codes,
		// but the inner store consumed someone else's code); treat as not-found
		return domain.Flow{}, store.ErrNotFound
	}
	f.ID = stripPrefix(s.tenantID, f.ID)
	return f, nil
}

func (s *FlowStore) DeleteExpired(now time.Time) (int, error) {
	// Delegate to the inner store — it cleans up all tenants' expired flows.
	// This is intentional: the cleanup scheduler holds a reference to the raw
	// store and calls DeleteExpired directly, not via a tenanted wrapper.
	return s.inner.DeleteExpired(now)
}

// ---- SessionStore ----

type SessionStore struct {
	inner    store.SessionStore
	tenantID string
}

func NewSessionStore(inner store.SessionStore, tenantID string) *SessionStore {
	return &SessionStore{inner: inner, tenantID: tenantID}
}

func (s *SessionStore) Create(sess domain.Session) (domain.Session, error) {
	sess.ID = addPrefix(s.tenantID, sess.ID)
	created, err := s.inner.Create(sess)
	if err != nil {
		return domain.Session{}, err
	}
	created.ID = stripPrefix(s.tenantID, created.ID)
	return created, nil
}

func (s *SessionStore) GetByID(id string) (domain.Session, error) {
	sess, err := s.inner.GetByID(addPrefix(s.tenantID, id))
	if err != nil {
		return domain.Session{}, err
	}
	sess.ID = stripPrefix(s.tenantID, sess.ID)
	return sess, nil
}

func (s *SessionStore) GetByRefreshToken(token string) (domain.Session, error) {
	sess, err := s.inner.GetByRefreshToken(token)
	if err != nil {
		return domain.Session{}, err
	}
	// Verify the session belongs to this tenant before returning it.
	if !hasPrefix(s.tenantID, sess.ID) {
		return domain.Session{}, store.ErrNotFound
	}
	sess.ID = stripPrefix(s.tenantID, sess.ID)
	return sess, nil
}

func (s *SessionStore) List() ([]domain.Session, error) {
	all, err := s.inner.List()
	if err != nil {
		return nil, err
	}
	var out []domain.Session
	for _, sess := range all {
		if hasPrefix(s.tenantID, sess.ID) {
			sess.ID = stripPrefix(s.tenantID, sess.ID)
			out = append(out, sess)
		}
	}
	return out, nil
}

func (s *SessionStore) Update(sess domain.Session) (domain.Session, error) {
	sess.ID = addPrefix(s.tenantID, sess.ID)
	updated, err := s.inner.Update(sess)
	if err != nil {
		return domain.Session{}, err
	}
	updated.ID = stripPrefix(s.tenantID, updated.ID)
	return updated, nil
}

func (s *SessionStore) Delete(id string) error {
	return s.inner.Delete(addPrefix(s.tenantID, id))
}

func (s *SessionStore) DeleteExpired(now time.Time) (int, error) {
	return s.inner.DeleteExpired(now)
}

// ---- AuditStore ----

type AuditStore struct {
	inner    store.AuditStore
	tenantID string
}

func NewAuditStore(inner store.AuditStore, tenantID string) *AuditStore {
	return &AuditStore{inner: inner, tenantID: tenantID}
}

func (s *AuditStore) Append(event domain.AuditEvent) {
	if event.Metadata == nil {
		event.Metadata = make(map[string]any)
	}
	event.Metadata["tenant_id"] = s.tenantID
	s.inner.Append(event)
}

func (s *AuditStore) List(filter store.AuditFilter) []domain.AuditEvent {
	all := s.inner.List(filter)
	var out []domain.AuditEvent
	for _, e := range all {
		if tid, ok := e.Metadata["tenant_id"].(string); ok && tid == s.tenantID {
			out = append(out, e)
		}
	}
	return out
}

func (s *AuditStore) Verify() (store.AuditVerifyResult, error) {
	return s.inner.Verify()
}

// ---- StoreSet and Dispatcher ----

// StoreSet holds the full set of per-tenant stores.
type StoreSet struct {
	Users    store.UserStore
	Groups   store.GroupStore
	Flows    store.FlowStore
	Sessions store.SessionStore
	Audit    store.AuditStore
}

// Dispatcher resolves the correct StoreSet for the tenant ID on the context.
// In single mode, it always returns the default StoreSet.
type Dispatcher struct {
	sets map[string]*StoreSet
	def  *StoreSet
}

// NewDispatcher builds a Dispatcher. The tenantID→StoreSet map must include an
// entry for tenant.DefaultTenantID; it is used as the fallback.
func NewDispatcher(sets map[string]*StoreSet) *Dispatcher {
	return &Dispatcher{
		sets: sets,
		def:  sets[tenant.DefaultTenantID],
	}
}

// ForContext returns the StoreSet for the tenant on the context.
// Falls back to the default StoreSet if no tenant is set or is unknown.
func (d *Dispatcher) ForContext(ctx context.Context) *StoreSet {
	tid := tenant.FromContext(ctx)
	if s, ok := d.sets[tid]; ok {
		return s
	}
	return d.def
}
