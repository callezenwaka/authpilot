package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"furnace/server/internal/authevents"
	"furnace/server/internal/domain"
	"furnace/server/internal/store"
	"furnace/server/internal/store/memory"
)

// --- in-memory APIKeyStore for tests ---

type memAPIKeyStore struct {
	mu   sync.Mutex
	keys map[string]domain.APIKey // keyed by ID
}

func newMemAPIKeyStore() *memAPIKeyStore {
	return &memAPIKeyStore{keys: make(map[string]domain.APIKey)}
}

func (s *memAPIKeyStore) Create(k domain.APIKey) (domain.APIKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[k.ID] = k
	return k, nil
}

func (s *memAPIKeyStore) GetByID(id string) (domain.APIKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok {
		return domain.APIKey{}, store.ErrNotFound
	}
	return k, nil
}

func (s *memAPIKeyStore) GetByHash(hash string) (domain.APIKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range s.keys {
		if k.KeyHash == hash {
			return k, nil
		}
	}
	return domain.APIKey{}, store.ErrNotFound
}

func (s *memAPIKeyStore) List() ([]domain.APIKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]domain.APIKey, 0, len(s.keys))
	for _, k := range s.keys {
		out = append(out, k)
	}
	return out, nil
}

func (s *memAPIKeyStore) Revoke(id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok || k.RevokedAt != nil {
		return store.ErrNotFound
	}
	k.RevokedAt = &at
	s.keys[id] = k
	return nil
}

func (s *memAPIKeyStore) UpdateLastUsed(id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok {
		return store.ErrNotFound
	}
	k.LastUsedAt = &at
	s.keys[id] = k
	return nil
}

// --- helpers ---

const testStaticKey = "static-test-key-1234567890"

func newAPIKeyRouter(ks store.APIKeyStore) http.Handler {
	return NewRouter(Dependencies{
		Users:         memory.NewUserStore(),
		Groups:        memory.NewGroupStore(),
		Flows:         memory.NewFlowStore(),
		Sessions:      memory.NewSessionStore(),
		APIKey:        testStaticKey,
		AuthEventSink: authevents.Noop(),
		APIKeyStore:   ks,
	})
}

func apiReq(method, path, body, key string) *http.Request {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r.Header.Set("X-Furnace-Api-Key", key)
	return r
}

// --- CRUD handler tests ---

func TestAPIKeyList_Empty(t *testing.T) {
	ks := newMemAPIKeyStore()
	h := newAPIKeyRouter(ks)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, apiReq(http.MethodGet, "/api/v1/api-keys", "", testStaticKey))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body)
	}
	var list []any
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("parse body: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("expected empty list, got %d items", len(list))
	}
}

func TestAPIKeyCreate(t *testing.T) {
	ks := newMemAPIKeyStore()
	h := newAPIKeyRouter(ks)

	body := `{"label":"ci-token","scopes":["read","write"]}`
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, apiReq(http.MethodPost, "/api/v1/api-keys", body, testStaticKey))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", rec.Code, rec.Body)
	}
	var resp apiKeyCreateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse body: %v", err)
	}
	if !strings.HasPrefix(resp.Key, "furn_") {
		t.Errorf("raw key should start with 'furn_', got %q", resp.Key)
	}
	if resp.ID == "" {
		t.Error("expected non-empty id")
	}
	if resp.Label != "ci-token" {
		t.Errorf("label = %q, want ci-token", resp.Label)
	}
}

func TestAPIKeyCreate_DefaultScopes(t *testing.T) {
	ks := newMemAPIKeyStore()
	h := newAPIKeyRouter(ks)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, apiReq(http.MethodPost, "/api/v1/api-keys", `{"label":"no-scopes"}`, testStaticKey))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d; body = %s", rec.Code, rec.Body)
	}
	var resp apiKeyCreateResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Scopes) != 2 || resp.Scopes[0] != "read" {
		t.Errorf("expected default scopes [read write], got %v", resp.Scopes)
	}
}

func TestAPIKeyCreate_InvalidScope(t *testing.T) {
	ks := newMemAPIKeyStore()
	h := newAPIKeyRouter(ks)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, apiReq(http.MethodPost, "/api/v1/api-keys", `{"label":"x","scopes":["superuser"]}`, testStaticKey))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestAPIKeyCreate_MissingLabel(t *testing.T) {
	ks := newMemAPIKeyStore()
	h := newAPIKeyRouter(ks)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, apiReq(http.MethodPost, "/api/v1/api-keys", `{"scopes":["read"]}`, testStaticKey))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestAPIKeyGetByID(t *testing.T) {
	ks := newMemAPIKeyStore()
	h := newAPIKeyRouter(ks)

	// Create via API.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, apiReq(http.MethodPost, "/api/v1/api-keys", `{"label":"get-test"}`, testStaticKey))
	var created apiKeyCreateResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &created)

	// Get by ID.
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, apiReq(http.MethodGet, "/api/v1/api-keys/"+created.ID, "", testStaticKey))

	if rec2.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec2.Code, rec2.Body)
	}
	var got apiKeyResponse
	_ = json.Unmarshal(rec2.Body.Bytes(), &got)
	if got.ID != created.ID {
		t.Errorf("id = %q, want %q", got.ID, created.ID)
	}
}

func TestAPIKeyGetByID_NotFound(t *testing.T) {
	ks := newMemAPIKeyStore()
	h := newAPIKeyRouter(ks)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, apiReq(http.MethodGet, "/api/v1/api-keys/ak_missing", "", testStaticKey))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestAPIKeyRevoke(t *testing.T) {
	ks := newMemAPIKeyStore()
	h := newAPIKeyRouter(ks)

	// Create.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, apiReq(http.MethodPost, "/api/v1/api-keys", `{"label":"revoke-test"}`, testStaticKey))
	var created apiKeyCreateResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &created)

	// Revoke.
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, apiReq(http.MethodDelete, "/api/v1/api-keys/"+created.ID, "", testStaticKey))
	if rec2.Code != http.StatusNoContent {
		t.Fatalf("revoke status = %d, want 204; body = %s", rec2.Code, rec2.Body)
	}

	// Get should show revoked_at.
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, apiReq(http.MethodGet, "/api/v1/api-keys/"+created.ID, "", testStaticKey))
	var got map[string]any
	_ = json.Unmarshal(rec3.Body.Bytes(), &got)
	if got["revoked_at"] == nil {
		t.Error("expected revoked_at to be set after revoke")
	}
}

func TestAPIKeyRevoke_NotFound(t *testing.T) {
	ks := newMemAPIKeyStore()
	h := newAPIKeyRouter(ks)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, apiReq(http.MethodDelete, "/api/v1/api-keys/ak_ghost", "", testStaticKey))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestAPIKeyList_AfterCreate(t *testing.T) {
	ks := newMemAPIKeyStore()
	h := newAPIKeyRouter(ks)

	h.ServeHTTP(httptest.NewRecorder(), apiReq(http.MethodPost, "/api/v1/api-keys", `{"label":"a"}`, testStaticKey))
	h.ServeHTTP(httptest.NewRecorder(), apiReq(http.MethodPost, "/api/v1/api-keys", `{"label":"b"}`, testStaticKey))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, apiReq(http.MethodGet, "/api/v1/api-keys", "", testStaticKey))

	var list []apiKeyResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(list))
	}
}

// --- middleware DB key authentication tests ---

func TestMiddleware_DBKeyAuth(t *testing.T) {
	ks := newMemAPIKeyStore()

	// Create a DB key directly.
	rawKey, hash, _ := generateAPIKey()
	k := domain.APIKey{
		ID:        "ak_test01",
		Label:     "test",
		KeyHash:   hash,
		Scopes:    []string{"read", "write"},
		CreatedAt: time.Now().UTC(),
	}
	_, _ = ks.Create(k)

	h := newAPIKeyRouter(ks)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/api-keys", nil)
	req.Header.Set("X-Furnace-Api-Key", rawKey)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("DB key auth failed: status = %d; body = %s", rec.Code, rec.Body)
	}
}

func TestMiddleware_RevokedDBKeyRejected(t *testing.T) {
	ks := newMemAPIKeyStore()

	rawKey, hash, _ := generateAPIKey()
	revokedAt := time.Now().UTC()
	k := domain.APIKey{
		ID:        "ak_revoked",
		Label:     "old",
		KeyHash:   hash,
		Scopes:    []string{"read"},
		CreatedAt: time.Now().UTC(),
		RevokedAt: &revokedAt,
	}
	_, _ = ks.Create(k)

	h := newAPIKeyRouter(ks)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/api-keys", nil)
	req.Header.Set("X-Furnace-Api-Key", rawKey)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked key should be rejected: status = %d", rec.Code)
	}
}

func TestMiddleware_UnknownKeyRejected(t *testing.T) {
	ks := newMemAPIKeyStore()
	h := newAPIKeyRouter(ks)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/api-keys", nil)
	req.Header.Set("X-Furnace-Api-Key", "furn_notinstore")
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unknown key should be rejected: status = %d", rec.Code)
	}
}

func TestMiddleware_StaticKeyStillWorks(t *testing.T) {
	ks := newMemAPIKeyStore()
	h := newAPIKeyRouter(ks)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, apiReq(http.MethodGet, "/api/v1/api-keys", "", testStaticKey))

	if rec.Code != http.StatusOK {
		t.Fatalf("static key should still work: status = %d", rec.Code)
	}
}
