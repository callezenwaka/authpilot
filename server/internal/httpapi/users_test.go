package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"furnace/server/internal/store/memory"
)

func newTestRouter() http.Handler {
	return NewRouter(Dependencies{
		Users:    memory.NewUserStore(),
		Groups:   memory.NewGroupStore(),
		Flows:    memory.NewFlowStore(),
		Sessions: memory.NewSessionStore(),
		APIKey:   "test-key",
	})
}

func apiPost(t *testing.T, router http.Handler, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Furnace-Api-Key", "test-key")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

func TestCreateUser_DuplicateEmail_Returns409(t *testing.T) {
	router := newTestRouter()

	user := map[string]any{"email": "alice@example.com", "display_name": "Alice", "active": true}

	rr := apiPost(t, router, "/api/v1/users", user)
	if rr.Code != http.StatusCreated {
		t.Fatalf("first create: expected 201, got %d: %s", rr.Code, rr.Body)
	}

	rr = apiPost(t, router, "/api/v1/users", user)
	if rr.Code != http.StatusConflict {
		t.Fatalf("duplicate create: expected 409, got %d: %s", rr.Code, rr.Body)
	}

	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	errObj, _ := resp["error"].(map[string]any)
	if errObj["code"] != "email_conflict" {
		t.Fatalf("expected error code %q, got %q", "email_conflict", errObj["code"])
	}
}

func TestCreateUser_UniqueEmails_BothSucceed(t *testing.T) {
	router := newTestRouter()

	rr := apiPost(t, router, "/api/v1/users", map[string]any{"email": "alice@example.com", "display_name": "Alice", "active": true})
	if rr.Code != http.StatusCreated {
		t.Fatalf("alice: expected 201, got %d", rr.Code)
	}

	rr = apiPost(t, router, "/api/v1/users", map[string]any{"email": "bob@example.com", "display_name": "Bob", "active": true})
	if rr.Code != http.StatusCreated {
		t.Fatalf("bob: expected 201, got %d", rr.Code)
	}
}
