// Package export converts Furnace users and groups into migration-ready formats.
// Supported formats: SCIM 2.0 (JSON), Okta CSV, Azure AD JSON, Google Workspace CSV.
package export

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"furnace/server/internal/domain"
)

// Format identifies an export format.
type Format string

const (
	FormatSCIM   Format = "scim"
	FormatOkta   Format = "okta"
	FormatAzure  Format = "azure"
	FormatGoogle Format = "google"
)

// ParseFormat normalises a raw format string, returning an error for unknowns.
func ParseFormat(s string) (Format, error) {
	switch Format(strings.ToLower(strings.TrimSpace(s))) {
	case FormatSCIM:
		return FormatSCIM, nil
	case FormatOkta:
		return FormatOkta, nil
	case FormatAzure:
		return FormatAzure, nil
	case FormatGoogle:
		return FormatGoogle, nil
	default:
		return "", fmt.Errorf("unknown export format %q; supported: scim, okta, azure, google", s)
	}
}

// ContentType returns the MIME type for the given format.
func ContentType(f Format) string {
	switch f {
	case FormatSCIM, FormatAzure:
		return "application/json"
	default:
		return "text/csv; charset=utf-8"
	}
}

// Filename returns a suggested download filename for the given format.
func Filename(f Format) string {
	ts := time.Now().UTC().Format("20060102-150405")
	switch f {
	case FormatSCIM:
		return fmt.Sprintf("furnace-export-scim-%s.json", ts)
	case FormatOkta:
		return fmt.Sprintf("furnace-export-okta-%s.csv", ts)
	case FormatAzure:
		return fmt.Sprintf("furnace-export-azure-%s.json", ts)
	case FormatGoogle:
		return fmt.Sprintf("furnace-export-google-%s.csv", ts)
	}
	return fmt.Sprintf("furnace-export-%s.txt", ts)
}

// Users renders users in the requested format.
func Users(users []domain.User, groups []domain.Group, f Format) ([]byte, error) {
	switch f {
	case FormatSCIM:
		return scimUsers(users, groups)
	case FormatOkta:
		return oktaCSV(users)
	case FormatAzure:
		return azureJSON(users, groups)
	case FormatGoogle:
		return googleCSV(users)
	}
	return nil, fmt.Errorf("unsupported format: %s", f)
}

// --- SCIM 2.0 ---

type scimListResponse struct {
	Schemas      []string    `json:"schemas"`
	TotalResults int         `json:"totalResults"`
	StartIndex   int         `json:"startIndex"`
	ItemsPerPage int         `json:"itemsPerPage"`
	Resources    []scimUser  `json:"Resources"`
}

type scimUser struct {
	Schemas     []string          `json:"schemas"`
	ID          string            `json:"id"`
	ExternalID  string            `json:"externalId,omitempty"`
	UserName    string            `json:"userName"`
	Name        scimName          `json:"name"`
	DisplayName string            `json:"displayName,omitempty"`
	Emails      []scimEmail       `json:"emails"`
	Groups      []scimGroupRef    `json:"groups,omitempty"`
	Active      bool              `json:"active"`
	Meta        scimMeta          `json:"meta"`
}

type scimName struct {
	Formatted  string `json:"formatted,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
}

type scimEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type"`
	Primary bool   `json:"primary"`
}

type scimGroupRef struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
}

type scimMeta struct {
	ResourceType string `json:"resourceType"`
	Created      string `json:"created"`
}

func scimUsers(users []domain.User, groups []domain.Group) ([]byte, error) {
	// Build group lookup for display names.
	groupByID := make(map[string]domain.Group, len(groups))
	for _, g := range groups {
		groupByID[g.ID] = g
	}

	resources := make([]scimUser, 0, len(users))
	for _, u := range users {
		groupRefs := make([]scimGroupRef, 0, len(u.Groups))
		for _, gid := range u.Groups {
			ref := scimGroupRef{Value: gid}
			if g, ok := groupByID[gid]; ok {
				ref.Display = g.DisplayName
				if ref.Display == "" {
					ref.Display = g.Name
				}
			}
			groupRefs = append(groupRefs, ref)
		}
		first, last := splitDisplayName(u.DisplayName)
		resources = append(resources, scimUser{
			Schemas:     []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
			ID:          u.ID,
			UserName:    u.Email,
			Name: scimName{
				Formatted:  u.DisplayName,
				GivenName:  first,
				FamilyName: last,
			},
			DisplayName: u.DisplayName,
			Emails:      []scimEmail{{Value: u.Email, Type: "work", Primary: true}},
			Groups:      groupRefs,
			Active:      u.Active,
			Meta: scimMeta{
				ResourceType: "User",
				Created:      u.CreatedAt.UTC().Format(time.RFC3339),
			},
		})
	}

	resp := scimListResponse{
		Schemas:      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		TotalResults: len(resources),
		StartIndex:   1,
		ItemsPerPage: len(resources),
		Resources:    resources,
	}
	return jsonIndent(resp)
}

// --- Okta CSV ---
// Columns match the Okta bulk import template.

func oktaCSV(users []domain.User) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)

	headers := []string{
		"login", "email", "firstName", "lastName",
		"displayName", "mobilePhone", "userType",
	}
	if err := w.Write(headers); err != nil {
		return nil, err
	}

	for _, u := range users {
		first, last := splitDisplayName(u.DisplayName)
		row := []string{
			u.Email,
			u.Email,
			first,
			last,
			u.DisplayName,
			u.PhoneNumber,
			"",
		}
		if err := w.Write(row); err != nil {
			return nil, err
		}
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

// --- Azure AD JSON ---
// Matches the Azure AD bulk import JSON schema.

type azureExport struct {
	Users  []azureUser  `json:"users"`
	Groups []azureGroup `json:"groups"`
}

type azureUser struct {
	UserPrincipalName string              `json:"userPrincipalName"`
	DisplayName       string              `json:"displayName"`
	GivenName         string              `json:"givenName,omitempty"`
	Surname           string              `json:"surname,omitempty"`
	MailNickname      string              `json:"mailNickname"`
	Mail              string              `json:"mail"`
	MobilePhone       string              `json:"mobilePhone,omitempty"`
	AccountEnabled    bool                `json:"accountEnabled"`
	PasswordProfile   azurePasswordProfile `json:"passwordProfile"`
	GroupMemberships  []string            `json:"groupMemberships,omitempty"`
}

type azurePasswordProfile struct {
	Password                      string `json:"password"`
	ForceChangePasswordNextSignIn bool   `json:"forceChangePasswordNextSignIn"`
}

type azureGroup struct {
	DisplayName     string   `json:"displayName"`
	MailNickname    string   `json:"mailNickname"`
	MailEnabled     bool     `json:"mailEnabled"`
	SecurityEnabled bool     `json:"securityEnabled"`
	Members         []string `json:"members,omitempty"`
}

func azureJSON(users []domain.User, groups []domain.Group) ([]byte, error) {
	azUsers := make([]azureUser, 0, len(users))
	for _, u := range users {
		nick := strings.Split(u.Email, "@")[0]
		first, last := splitDisplayName(u.DisplayName)
		azUsers = append(azUsers, azureUser{
			UserPrincipalName: u.Email,
			DisplayName:       u.DisplayName,
			GivenName:         first,
			Surname:           last,
			MailNickname:      nick,
			Mail:              u.Email,
			MobilePhone:       u.PhoneNumber,
			AccountEnabled:    u.Active,
			PasswordProfile: azurePasswordProfile{
				Password:                      "ChangeMe123!",
				ForceChangePasswordNextSignIn: true,
			},
			GroupMemberships: u.Groups,
		})
	}

	azGroups := make([]azureGroup, 0, len(groups))
	for _, g := range groups {
		nick := strings.ToLower(strings.ReplaceAll(g.Name, " ", "-"))
		azGroups = append(azGroups, azureGroup{
			DisplayName:     g.DisplayName,
			MailNickname:    nick,
			MailEnabled:     false,
			SecurityEnabled: true,
			Members:         g.MemberIDs,
		})
	}

	return jsonIndent(azureExport{Users: azUsers, Groups: azGroups})
}

// --- Google Workspace CSV ---
// Columns match the Google Workspace Directory bulk upload template.

func googleCSV(users []domain.User) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)

	headers := []string{
		"First Name [Required]",
		"Last Name [Required]",
		"Email Address [Required]",
		"Password [Required]",
		"Password Hash Function [UPLOAD ONLY]",
		"Org Unit Path [Required]",
		"New Primary Email [UPLOAD ONLY]",
		"Recovery Email",
		"Home Secondary Email",
		"Work Secondary Email",
		"Recovery Phone [MUST BE IN THE E.164 FORMAT]",
		"Work Phone",
		"Home Phone",
		"Mobile Phone",
		"Work Address",
		"Home Address",
		"Employee ID",
		"Employee Type",
		"Employee Title",
		"Manager Email",
		"Department",
		"Cost Center",
		"Building ID",
		"Floor Name",
		"Floor Section",
		"Change Password at Next Sign-In",
	}
	if err := w.Write(headers); err != nil {
		return nil, err
	}

	for _, u := range users {
		first, last := splitDisplayName(u.DisplayName)
		row := make([]string, len(headers))
		row[0] = first
		row[1] = last
		row[2] = u.Email
		row[3] = "ChangeMe123!" // placeholder — user must reset on first login
		row[4] = ""
		row[5] = "/"
		// index 13 = Mobile Phone
		row[13] = u.PhoneNumber
		// index 25 = Change Password at Next Sign-In
		row[25] = "TRUE"
		if err := w.Write(row); err != nil {
			return nil, err
		}
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

// --- helpers ---

func splitDisplayName(name string) (first, last string) {
	parts := strings.Fields(name)
	switch len(parts) {
	case 0:
		return "", ""
	case 1:
		return parts[0], ""
	default:
		return parts[0], strings.Join(parts[1:], " ")
	}
}

func jsonIndent(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("export: marshal json: %w", err)
	}
	return b, nil
}
