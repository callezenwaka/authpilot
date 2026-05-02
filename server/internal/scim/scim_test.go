package scim

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"furnace/server/internal/store/memory"
)

func newTestRouter() http.Handler {
	return NewRouter(RouterDeps{
		Users:  memory.NewUserStore(),
		Groups: memory.NewGroupStore(),
	})
}

func do(t *testing.T, r http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reqBody *bytes.Reader
	if body != "" {
		reqBody = bytes.NewReader([]byte(body))
	} else {
		reqBody = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reqBody)
	if body != "" {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// --- ServiceProviderConfig ---

func TestServiceProviderConfig(t *testing.T) {
	r := newTestRouter()
	rec := do(t, r, http.MethodGet, "/scim/v2/ServiceProviderConfig", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if _, ok := body["patch"]; !ok {
		t.Error("expected 'patch' field in ServiceProviderConfig")
	}
}

// --- Schemas ---

func TestSchemas(t *testing.T) {
	r := newTestRouter()
	rec := do(t, r, http.MethodGet, "/scim/v2/Schemas", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp listResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if resp.TotalResults != 2 {
		t.Errorf("TotalResults = %d, want 2", resp.TotalResults)
	}
}

func TestSchemaByID_User(t *testing.T) {
	r := newTestRouter()
	rec := do(t, r, http.MethodGet, "/scim/v2/Schemas/"+schemaUser, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestSchemaByID_NotFound(t *testing.T) {
	r := newTestRouter()
	rec := do(t, r, http.MethodGet, "/scim/v2/Schemas/urn:unknown", "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

// --- Users CRUD ---

func TestCreateAndGetUser(t *testing.T) {
	r := newTestRouter()

	body := `{"userName":"alice@example.com","displayName":"Alice","emails":[{"value":"alice@example.com","primary":true}]}`
	rec := do(t, r, http.MethodPost, "/scim/v2/Users", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201; body: %s", rec.Code, rec.Body.String())
	}

	var created scimUser
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if created.UserName != "alice@example.com" {
		t.Errorf("userName = %q, want alice@example.com", created.UserName)
	}
	if !created.Active {
		t.Error("expected Active=true")
	}
	if created.ID == "" {
		t.Error("expected non-empty ID")
	}

	// GET by ID
	rec2 := do(t, r, http.MethodGet, "/scim/v2/Users/"+created.ID, "")
	if rec2.Code != http.StatusOK {
		t.Fatalf("get status = %d, want 200", rec2.Code)
	}
}

func TestListUsers_Empty(t *testing.T) {
	r := newTestRouter()
	rec := do(t, r, http.MethodGet, "/scim/v2/Users", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp listResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if resp.TotalResults != 0 {
		t.Errorf("TotalResults = %d, want 0", resp.TotalResults)
	}
}

func TestListUsers_Filter(t *testing.T) {
	r := newTestRouter()
	do(t, r, http.MethodPost, "/scim/v2/Users", `{"userName":"alice@example.com","displayName":"Alice"}`)
	do(t, r, http.MethodPost, "/scim/v2/Users", `{"userName":"bob@example.com","displayName":"Bob"}`)

	rec := do(t, r, http.MethodGet, `/scim/v2/Users?filter=userName+eq+%22alice%40example.com%22`, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp listResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if resp.TotalResults != 1 {
		t.Errorf("TotalResults = %d, want 1", resp.TotalResults)
	}
}

func TestListUsers_GroupRefs(t *testing.T) {
	r := newTestRouter()

	// Create a user via SCIM.
	urec := do(t, r, http.MethodPost, "/scim/v2/Users", `{"userName":"alice@example.com","displayName":"Alice"}`)
	if urec.Code != http.StatusCreated {
		t.Fatalf("create user: status = %d", urec.Code)
	}
	var created scimUser
	_ = json.Unmarshal(urec.Body.Bytes(), &created)

	// Create a group that includes the user.
	grec := do(t, r, http.MethodPost, "/scim/v2/Groups",
		`{"displayName":"Engineering","members":[{"value":"`+created.ID+`"}]}`)
	if grec.Code != http.StatusCreated {
		t.Fatalf("create group: status = %d", grec.Code)
	}
	var createdGroup scimGroup
	_ = json.Unmarshal(grec.Body.Bytes(), &createdGroup)

	// List users — the user's groups field must reference the group.
	rec := do(t, r, http.MethodGet, "/scim/v2/Users", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list users: status = %d", rec.Code)
	}
	var resp listResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if resp.TotalResults != 1 {
		t.Fatalf("TotalResults = %d, want 1", resp.TotalResults)
	}
	raw, _ := json.Marshal(resp.Resources[0])
	var u scimUser
	_ = json.Unmarshal(raw, &u)
	if len(u.Groups) != 1 {
		t.Fatalf("user.groups len = %d, want 1", len(u.Groups))
	}
	if u.Groups[0].Value != createdGroup.ID {
		t.Errorf("user.groups[0].value = %q, want %q", u.Groups[0].Value, createdGroup.ID)
	}
}

func TestReplaceUser(t *testing.T) {
	r := newTestRouter()
	rec := do(t, r, http.MethodPost, "/scim/v2/Users", `{"userName":"alice@example.com","displayName":"Alice"}`)
	var created scimUser
	_ = json.Unmarshal(rec.Body.Bytes(), &created)

	rec2 := do(t, r, http.MethodPut, "/scim/v2/Users/"+created.ID,
		`{"userName":"alice@example.com","displayName":"Alice Updated"}`)
	if rec2.Code != http.StatusOK {
		t.Fatalf("replace status = %d, want 200", rec2.Code)
	}
	var updated scimUser
	_ = json.Unmarshal(rec2.Body.Bytes(), &updated)
	if updated.DisplayName != "Alice Updated" {
		t.Errorf("displayName = %q, want 'Alice Updated'", updated.DisplayName)
	}
}

func TestPatchUser(t *testing.T) {
	r := newTestRouter()
	rec := do(t, r, http.MethodPost, "/scim/v2/Users", `{"userName":"alice@example.com","displayName":"Alice"}`)
	var created scimUser
	_ = json.Unmarshal(rec.Body.Bytes(), &created)

	patch := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Alice Patched"}]}`
	rec2 := do(t, r, http.MethodPatch, "/scim/v2/Users/"+created.ID, patch)
	if rec2.Code != http.StatusOK {
		t.Fatalf("patch status = %d, want 200", rec2.Code)
	}
	var updated scimUser
	_ = json.Unmarshal(rec2.Body.Bytes(), &updated)
	if updated.DisplayName != "Alice Patched" {
		t.Errorf("displayName = %q, want 'Alice Patched'", updated.DisplayName)
	}
}

func TestDeleteUser(t *testing.T) {
	r := newTestRouter()
	rec := do(t, r, http.MethodPost, "/scim/v2/Users", `{"userName":"alice@example.com"}`)
	var created scimUser
	_ = json.Unmarshal(rec.Body.Bytes(), &created)

	rec2 := do(t, r, http.MethodDelete, "/scim/v2/Users/"+created.ID, "")
	if rec2.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204", rec2.Code)
	}

	rec3 := do(t, r, http.MethodGet, "/scim/v2/Users/"+created.ID, "")
	if rec3.Code != http.StatusNotFound {
		t.Errorf("get-after-delete status = %d, want 404", rec3.Code)
	}
}

func TestCreateUser_MissingUserName(t *testing.T) {
	r := newTestRouter()
	rec := do(t, r, http.MethodPost, "/scim/v2/Users", `{"displayName":"No Email"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestGetUser_NotFound(t *testing.T) {
	r := newTestRouter()
	rec := do(t, r, http.MethodGet, "/scim/v2/Users/does-not-exist", "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

// --- Groups CRUD ---

func TestCreateAndGetGroup(t *testing.T) {
	r := newTestRouter()
	rec := do(t, r, http.MethodPost, "/scim/v2/Groups", `{"displayName":"Engineering"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201; body: %s", rec.Code, rec.Body.String())
	}
	var created scimGroup
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if created.DisplayName != "Engineering" {
		t.Errorf("displayName = %q, want Engineering", created.DisplayName)
	}
	if created.ID == "" {
		t.Error("expected non-empty ID")
	}

	rec2 := do(t, r, http.MethodGet, "/scim/v2/Groups/"+created.ID, "")
	if rec2.Code != http.StatusOK {
		t.Fatalf("get status = %d, want 200", rec2.Code)
	}
}

func TestPatchGroup_AddRemoveMembers(t *testing.T) {
	r := newTestRouter()

	// Create a user and a group.
	urec := do(t, r, http.MethodPost, "/scim/v2/Users", `{"userName":"alice@example.com"}`)
	var u scimUser
	_ = json.Unmarshal(urec.Body.Bytes(), &u)

	grec := do(t, r, http.MethodPost, "/scim/v2/Groups", `{"displayName":"Eng"}`)
	var g scimGroup
	_ = json.Unmarshal(grec.Body.Bytes(), &g)

	// Add member.
	addPatch := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"add","path":"members","value":[{"value":"` + u.ID + `"}]}]}`
	rec := do(t, r, http.MethodPatch, "/scim/v2/Groups/"+g.ID, addPatch)
	if rec.Code != http.StatusOK {
		t.Fatalf("add-member status = %d, want 200", rec.Code)
	}
	var updated scimGroup
	_ = json.Unmarshal(rec.Body.Bytes(), &updated)
	if len(updated.Members) != 1 || updated.Members[0].Value != u.ID {
		t.Errorf("members after add = %+v, want [{%s}]", updated.Members, u.ID)
	}

	// Remove member.
	rmPatch := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove","path":"members","value":[{"value":"` + u.ID + `"}]}]}`
	rec2 := do(t, r, http.MethodPatch, "/scim/v2/Groups/"+g.ID, rmPatch)
	if rec2.Code != http.StatusOK {
		t.Fatalf("remove-member status = %d, want 200", rec2.Code)
	}
	var updated2 scimGroup
	_ = json.Unmarshal(rec2.Body.Bytes(), &updated2)
	if len(updated2.Members) != 0 {
		t.Errorf("members after remove = %+v, want []", updated2.Members)
	}
}

func TestDeleteGroup(t *testing.T) {
	r := newTestRouter()
	rec := do(t, r, http.MethodPost, "/scim/v2/Groups", `{"displayName":"Temp"}`)
	var g scimGroup
	_ = json.Unmarshal(rec.Body.Bytes(), &g)

	rec2 := do(t, r, http.MethodDelete, "/scim/v2/Groups/"+g.ID, "")
	if rec2.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204", rec2.Code)
	}
}

func TestCreateGroup_MissingDisplayName(t *testing.T) {
	r := newTestRouter()
	rec := do(t, r, http.MethodPost, "/scim/v2/Groups", `{"members":[]}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// --- Content-Type ---

func TestContentType_SCIM(t *testing.T) {
	r := newTestRouter()
	rec := do(t, r, http.MethodGet, "/scim/v2/Users", "")
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/scim+json") {
		t.Errorf("Content-Type = %q, want application/scim+json", ct)
	}
}

// --- matchesFilter ---

func TestMatchesFilter(t *testing.T) {
	u := scimUser{UserName: "alice@example.com", DisplayName: "Alice"}
	cases := []struct {
		filter string
		want   bool
	}{
		{"", true},
		{`userName eq "alice@example.com"`, true},
		{`userName eq "bob@example.com"`, false},
		{`displayName eq "Alice"`, true},
		{`displayName eq "Bob"`, false},
		{"unsupported filter syntax", true}, // passthrough
	}
	for _, c := range cases {
		got := matchesFilter(u, c.filter)
		if got != c.want {
			t.Errorf("matchesFilter(%q) = %v, want %v", c.filter, got, c.want)
		}
	}
}
