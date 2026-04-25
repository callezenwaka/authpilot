package export

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"furnace/server/internal/domain"
)

var testUsers = []domain.User{
	{
		ID:          "u1",
		Email:       "alice@example.com",
		DisplayName: "Alice Smith",
		Groups:      []string{"g1"},
		PhoneNumber: "+15551234567",
		CreatedAt:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	},
	{
		ID:          "u2",
		Email:       "bob@example.com",
		DisplayName: "Bob",
		CreatedAt:   time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
	},
}

var testGroups = []domain.Group{
	{ID: "g1", Name: "engineering", DisplayName: "Engineering", MemberIDs: []string{"u1"}},
}

func TestParseFormat(t *testing.T) {
	cases := []struct {
		in      string
		want    Format
		wantErr bool
	}{
		{"scim", FormatSCIM, false},
		{"SCIM", FormatSCIM, false},
		{"okta", FormatOkta, false},
		{"azure", FormatAzure, false},
		{"google", FormatGoogle, false},
		{"unknown", "", true},
		{"", "", true},
	}
	for _, c := range cases {
		got, err := ParseFormat(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseFormat(%q): expected error, got nil", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseFormat(%q): unexpected error: %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("ParseFormat(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestExportSCIM(t *testing.T) {
	data, err := Users(testUsers, testGroups, FormatSCIM)
	if err != nil {
		t.Fatalf("SCIM export error: %v", err)
	}
	var resp scimListResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("SCIM output is not valid JSON: %v", err)
	}
	if resp.TotalResults != 2 {
		t.Errorf("TotalResults = %d, want 2", resp.TotalResults)
	}
	found := false
	for _, u := range resp.Resources {
		if u.UserName == "alice@example.com" {
			found = true
			if len(u.Groups) != 1 || u.Groups[0].Value != "g1" {
				t.Errorf("alice group ref = %+v, want [{g1 Engineering}]", u.Groups)
			}
			// RFC 7643 §4.1.1 name attribute
			if u.Name.GivenName != "Alice" {
				t.Errorf("name.givenName = %q, want Alice", u.Name.GivenName)
			}
			if u.Name.FamilyName != "Smith" {
				t.Errorf("name.familyName = %q, want Smith", u.Name.FamilyName)
			}
			if u.Name.Formatted != "Alice Smith" {
				t.Errorf("name.formatted = %q, want Alice Smith", u.Name.Formatted)
			}
			// active reflects the user's actual Active field (false in test fixture)
			if u.Active {
				t.Error("expected Active=false for inactive test user")
			}
		}
	}
	if !found {
		t.Error("alice not found in SCIM output")
	}
}

func TestExportSCIM_Schema(t *testing.T) {
	data, _ := Users(testUsers, testGroups, FormatSCIM)
	var resp scimListResponse
	json.Unmarshal(data, &resp)
	wantListSchema := "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	if len(resp.Schemas) == 0 || resp.Schemas[0] != wantListSchema {
		t.Errorf("list schemas = %v, want [%s]", resp.Schemas, wantListSchema)
	}
	wantUserSchema := "urn:ietf:params:scim:schemas:core:2.0:User"
	for _, u := range resp.Resources {
		if len(u.Schemas) == 0 || u.Schemas[0] != wantUserSchema {
			t.Errorf("user %q schemas = %v, want [%s]", u.UserName, u.Schemas, wantUserSchema)
		}
	}
}

func TestExportOkta(t *testing.T) {
	data, err := Users(testUsers, testGroups, FormatOkta)
	if err != nil {
		t.Fatalf("Okta CSV export error: %v", err)
	}
	s := string(data)
	if !strings.Contains(s, "login") {
		t.Error("expected header row with 'login'")
	}
	if !strings.Contains(s, "alice@example.com") {
		t.Error("expected alice in Okta CSV")
	}
	if !strings.Contains(s, "Alice") {
		t.Error("expected first name in Okta CSV")
	}
}

func TestExportAzure(t *testing.T) {
	data, err := Users(testUsers, testGroups, FormatAzure)
	if err != nil {
		t.Fatalf("Azure JSON export error: %v", err)
	}
	var out azureExport
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("Azure output is not valid JSON: %v", err)
	}
	if len(out.Users) != 2 {
		t.Errorf("Users count = %d, want 2", len(out.Users))
	}
	if len(out.Groups) != 1 {
		t.Errorf("Groups count = %d, want 1", len(out.Groups))
	}
	alice := out.Users[0]
	if alice.UserPrincipalName != "alice@example.com" {
		t.Errorf("UPN = %q, want alice@example.com", alice.UserPrincipalName)
	}
	// Graph API required fields
	if alice.PasswordProfile.Password == "" {
		t.Error("passwordProfile.password must not be empty")
	}
	if !alice.PasswordProfile.ForceChangePasswordNextSignIn {
		t.Error("expected forceChangePasswordNextSignIn=true")
	}
	// givenName / surname for Graph API
	if alice.GivenName != "Alice" {
		t.Errorf("givenName = %q, want Alice", alice.GivenName)
	}
	if alice.Surname != "Smith" {
		t.Errorf("surname = %q, want Smith", alice.Surname)
	}
}

func TestExportGoogle(t *testing.T) {
	data, err := Users(testUsers, testGroups, FormatGoogle)
	if err != nil {
		t.Fatalf("Google CSV export error: %v", err)
	}
	s := string(data)
	if !strings.Contains(s, "First Name") {
		t.Error("expected Google CSV header")
	}
	if !strings.Contains(s, "alice@example.com") {
		t.Error("expected alice in Google CSV")
	}
	// Change Password at Next Sign-In must be TRUE (required for new accounts)
	if !strings.Contains(s, "TRUE") {
		t.Error("expected Change Password at Next Sign-In = TRUE")
	}
	// Phone number should be populated for users who have one
	if !strings.Contains(s, "+15551234567") {
		t.Error("expected alice's phone number in Mobile Phone column")
	}
}

func TestSplitDisplayName(t *testing.T) {
	cases := []struct{ in, first, last string }{
		{"Alice Smith", "Alice", "Smith"},
		{"Bob", "Bob", ""},
		{"", "", ""},
		{"Mary Jane Watson", "Mary", "Jane Watson"},
	}
	for _, c := range cases {
		f, l := splitDisplayName(c.in)
		if f != c.first || l != c.last {
			t.Errorf("splitDisplayName(%q) = (%q, %q), want (%q, %q)", c.in, f, l, c.first, c.last)
		}
	}
}

func TestContentType(t *testing.T) {
	if ContentType(FormatSCIM) != "application/json" {
		t.Error("SCIM should be application/json")
	}
	if ContentType(FormatAzure) != "application/json" {
		t.Error("Azure should be application/json")
	}
	if !strings.HasPrefix(ContentType(FormatOkta), "text/csv") {
		t.Error("Okta should be text/csv")
	}
	if !strings.HasPrefix(ContentType(FormatGoogle), "text/csv") {
		t.Error("Google should be text/csv")
	}
}
