package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"furnace/server/internal/domain"
	"furnace/server/internal/store/memory"
)

// fakeScimClient captures calls instead of making real HTTP requests.
type fakeScimClient struct {
	created []domain.User
	updated []domain.User
	deleted []string
}

func (f *fakeScimClient) UserCreated(u domain.User) { f.created = append(f.created, u) }
func (f *fakeScimClient) UserUpdated(u domain.User) { f.updated = append(f.updated, u) }
func (f *fakeScimClient) UserDeleted(id string)     { f.deleted = append(f.deleted, id) }

func newSCIMRouter(t *testing.T, sc SCIMClient, events SCIMEventLister) http.Handler {
	t.Helper()
	return NewRouter(Dependencies{
		Users:      memory.NewUserStore(),
		Groups:     memory.NewGroupStore(),
		Flows:      memory.NewFlowStore(),
		Sessions:   memory.NewSessionStore(),
		APIKey:     "test-key",
		SCIMClient: sc,
		SCIMEvents: events,
	})
}

func TestSCIMEvents_NotEnabled_Returns501(t *testing.T) {
	r := newSCIMRouter(t, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scim/events", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d", rr.Code)
	}
}

func TestSCIMEvents_EmptyList(t *testing.T) {
	events := memory.NewSCIMEventStore(100)
	r := newSCIMRouter(t, nil, events)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scim/events", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var list []any
	if err := json.NewDecoder(rr.Body).Decode(&list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("expected empty list, got %d items", len(list))
	}
}

func TestSCIMEvents_ReturnsList(t *testing.T) {
	events := memory.NewSCIMEventStore(100)
	events.Append(domain.SCIMEvent{
		Timestamp:      time.Now().UTC(),
		Method:         "POST",
		URL:            "http://scim.example.com/Users",
		ResponseStatus: 201,
	})
	r := newSCIMRouter(t, nil, events)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scim/events", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var list []map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 event, got %d", len(list))
	}
	if list[0]["method"] != "POST" {
		t.Fatalf("expected method=POST, got %v", list[0]["method"])
	}
}

func TestCreateUser_CallsSCIMClient(t *testing.T) {
	sc := &fakeScimClient{}
	r := newSCIMRouter(t, sc, nil)

	body, _ := json.Marshal(map[string]any{"id": "u1", "email": "a@b.com"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}
	if len(sc.created) != 1 || sc.created[0].ID != "u1" {
		t.Fatalf("expected UserCreated called with u1, got %v", sc.created)
	}
}

func TestUpdateUser_CallsSCIMClient(t *testing.T) {
	sc := &fakeScimClient{}
	users := memory.NewUserStore()
	_, _ = users.Create(domain.User{ID: "u1", Email: "a@b.com", Active: true})

	r := NewRouter(Dependencies{
		Users:      users,
		Groups:     memory.NewGroupStore(),
		Flows:      memory.NewFlowStore(),
		Sessions:   memory.NewSessionStore(),
		APIKey:     "test-key",
		SCIMClient: sc,
	})

	body, _ := json.Marshal(map[string]any{"id": "u1", "email": "b@b.com"})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/users/u1", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if len(sc.updated) != 1 || sc.updated[0].ID != "u1" {
		t.Fatalf("expected UserUpdated called with u1, got %v", sc.updated)
	}
}

func TestDeleteUser_CallsSCIMClient(t *testing.T) {
	sc := &fakeScimClient{}
	users := memory.NewUserStore()
	_, _ = users.Create(domain.User{ID: "u1", Email: "a@b.com", Active: true})

	r := NewRouter(Dependencies{
		Users:      users,
		Groups:     memory.NewGroupStore(),
		Flows:      memory.NewFlowStore(),
		Sessions:   memory.NewSessionStore(),
		APIKey:     "test-key",
		SCIMClient: sc,
	})

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/u1", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
	if len(sc.deleted) != 1 || sc.deleted[0] != "u1" {
		t.Fatalf("expected UserDeleted called with u1, got %v", sc.deleted)
	}
}

func TestCreateUser_SyncsGroupMemberIDs(t *testing.T) {
	groups := memory.NewGroupStore()
	g, _ := groups.Create(domain.Group{
		ID:          "grp_eng",
		Name:        "engineering",
		DisplayName: "Engineering",
		CreatedAt:   time.Now().UTC(),
	})

	r := NewRouter(Dependencies{
		Users:    memory.NewUserStore(),
		Groups:   groups,
		Flows:    memory.NewFlowStore(),
		Sessions: memory.NewSessionStore(),
		APIKey:   "test-key",
	})

	body, _ := json.Marshal(map[string]any{
		"id":     "u1",
		"email":  "alice@example.com",
		"groups": []string{g.ID},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}
	updated, _ := groups.GetByID(g.ID)
	if len(updated.MemberIDs) != 1 || updated.MemberIDs[0] != "u1" {
		t.Errorf("group.MemberIDs = %v, want [u1]", updated.MemberIDs)
	}
}

func TestUpdateUser_SyncsGroupMemberIDs(t *testing.T) {
	users := memory.NewUserStore()
	groups := memory.NewGroupStore()

	// User starts in no groups.
	_, _ = users.Create(domain.User{ID: "u1", Email: "alice@example.com", Active: true, CreatedAt: time.Now().UTC()})
	g, _ := groups.Create(domain.Group{
		ID:          "grp_eng",
		Name:        "engineering",
		DisplayName: "Engineering",
		CreatedAt:   time.Now().UTC(),
	})

	r := NewRouter(Dependencies{
		Users:    users,
		Groups:   groups,
		Flows:    memory.NewFlowStore(),
		Sessions: memory.NewSessionStore(),
		APIKey:   "test-key",
	})

	// Update user to add them to the group.
	body, _ := json.Marshal(map[string]any{
		"email":  "alice@example.com",
		"groups": []string{g.ID},
	})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/users/u1", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	updated, _ := groups.GetByID(g.ID)
	if len(updated.MemberIDs) != 1 || updated.MemberIDs[0] != "u1" {
		t.Errorf("group.MemberIDs = %v, want [u1]", updated.MemberIDs)
	}
}

func TestCreateUser_NilSCIMClient_DoesNotPanic(t *testing.T) {
	r := newSCIMRouter(t, nil, nil)
	body, _ := json.Marshal(map[string]any{"id": "u1", "email": "a@b.com"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", rr.Code)
	}
}
