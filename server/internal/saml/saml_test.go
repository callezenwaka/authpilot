package saml

import (
	"encoding/base64"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"furnace/server/internal/domain"
	"furnace/server/internal/store/memory"
)

// --- CertManager tests ---

func TestNewCertManagerFromPath_RoundTrip(t *testing.T) {
	dir := t.TempDir()

	cm1, err := NewCertManagerFromPath(dir)
	if err != nil {
		t.Fatalf("first NewCertManagerFromPath() error: %v", err)
	}
	der1 := cm1.CertDER()

	// Second call should reload the same cert.
	cm2, err := NewCertManagerFromPath(dir)
	if err != nil {
		t.Fatalf("second NewCertManagerFromPath() error: %v", err)
	}
	der2 := cm2.CertDER()

	if string(der1) != string(der2) {
		t.Error("expected same certificate on reload")
	}
}

func TestNewCertManagerFromPath_EmptyDir(t *testing.T) {
	// Empty dir string should fall back to ephemeral generation.
	cm, err := NewCertManagerFromPath("")
	if err != nil {
		t.Fatalf("NewCertManagerFromPath(\"\") error: %v", err)
	}
	if cm.PrivateKey() == nil {
		t.Error("expected non-nil private key")
	}
}

func TestNewCertManager(t *testing.T) {
	cm, err := NewCertManager()
	if err != nil {
		t.Fatalf("NewCertManager() error: %v", err)
	}
	if cm.PrivateKey() == nil {
		t.Error("expected non-nil private key")
	}
	if cm.Certificate() == nil {
		t.Error("expected non-nil certificate")
	}
	if len(cm.CertDER()) == 0 {
		t.Error("expected non-empty DER bytes")
	}
	pem := cm.CertPEM()
	if !strings.Contains(string(pem), "BEGIN CERTIFICATE") {
		t.Error("CertPEM() should contain BEGIN CERTIFICATE")
	}
}

func TestCertManagerKeys(t *testing.T) {
	cm, err := NewCertManager()
	if err != nil {
		t.Fatal(err)
	}
	// Two calls should return the same key.
	k1 := cm.PrivateKey()
	k2 := cm.PrivateKey()
	if k1 != k2 {
		t.Error("expected same private key on repeated calls")
	}
}

// --- Metadata tests ---

func TestBuildMetadata(t *testing.T) {
	cm, err := NewCertManager()
	if err != nil {
		t.Fatal(err)
	}
	data, err := BuildMetadata("https://idp.example.com", "https://idp.example.com/saml/sso", cm)
	if err != nil {
		t.Fatalf("BuildMetadata() error: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty metadata")
	}
	// Must be valid XML.
	var ed EntityDescriptor
	if err := xml.Unmarshal(data, &ed); err != nil {
		t.Fatalf("metadata is not valid XML: %v", err)
	}
	if ed.EntityID != "https://idp.example.com" {
		t.Errorf("entityID = %q, want %q", ed.EntityID, "https://idp.example.com")
	}
	if len(ed.IDPSSODescriptor.SingleSignOnServices) == 0 {
		t.Error("expected at least one SingleSignOnService")
	}
	if len(ed.IDPSSODescriptor.KeyDescriptors) == 0 {
		t.Error("expected at least one KeyDescriptor")
	}
}

// --- AuthnRequest parsing tests ---

func TestParseAuthnRequest_Valid(t *testing.T) {
	// Build a minimal AuthnRequest XML and base64-encode it.
	xmlStr := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_testreqid" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" Destination="https://idp.example.com/saml/sso" AssertionConsumerServiceURL="https://sp.example.com/acs"><saml:Issuer>https://sp.example.com</saml:Issuer></samlp:AuthnRequest>`
	encoded := base64.StdEncoding.EncodeToString([]byte(xmlStr))

	req, err := ParseAuthnRequest(encoded)
	if err != nil {
		t.Fatalf("ParseAuthnRequest() error: %v", err)
	}
	if req.ID != "_testreqid" {
		t.Errorf("ID = %q, want %q", req.ID, "_testreqid")
	}
	if req.AssertionConsumerServiceURL != "https://sp.example.com/acs" {
		t.Errorf("ACS = %q, want %q", req.AssertionConsumerServiceURL, "https://sp.example.com/acs")
	}
}

func TestParseAuthnRequest_MissingID(t *testing.T) {
	xmlStr := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">sp</saml:Issuer></samlp:AuthnRequest>`
	encoded := base64.StdEncoding.EncodeToString([]byte(xmlStr))
	_, err := ParseAuthnRequest(encoded)
	if err == nil {
		t.Error("expected error for missing ID, got nil")
	}
}

func TestParseAuthnRequest_InvalidBase64(t *testing.T) {
	_, err := ParseAuthnRequest("not_valid_base64!!!")
	if err == nil {
		t.Error("expected error for invalid base64, got nil")
	}
}

// --- Assertion / Response tests ---

func TestBuildSignedResponse(t *testing.T) {
	cm, err := NewCertManager()
	if err != nil {
		t.Fatal(err)
	}
	user := domain.User{
		ID:          "user-1",
		Email:       "alice@example.com",
		DisplayName: "Alice",
	}
	cfg := AssertionConfig{
		IssuerEntityID: "https://idp.example.com",
		ACS:            "https://sp.example.com/acs",
		Audience:       "https://sp.example.com",
		InResponseTo:   "_testreqid",
		SessionTTL:     1 * time.Hour,
	}
	responseXML, err := BuildSignedResponse(cfg, user, cm)
	if err != nil {
		t.Fatalf("BuildSignedResponse() error: %v", err)
	}
	if len(responseXML) == 0 {
		t.Fatal("expected non-empty response XML")
	}
	xmlStr := string(responseXML)
	if !strings.Contains(xmlStr, "alice@example.com") {
		t.Error("expected email in assertion")
	}
	if !strings.Contains(xmlStr, "ds:Signature") {
		t.Error("expected ds:Signature in signed response")
	}
	if !strings.Contains(xmlStr, "ds:DigestValue") {
		t.Error("expected ds:DigestValue in signature")
	}
	if !strings.Contains(xmlStr, statusSuccess) {
		t.Errorf("expected status %q in response", statusSuccess)
	}
}

func TestBuildSignedResponse_NoEmail(t *testing.T) {
	cm, err := NewCertManager()
	if err != nil {
		t.Fatal(err)
	}
	user := domain.User{ID: "user-2"} // no email
	cfg := AssertionConfig{
		IssuerEntityID: "https://idp.example.com",
		ACS:            "https://sp.example.com/acs",
		SessionTTL:     1 * time.Hour,
	}
	responseXML, err := BuildSignedResponse(cfg, user, cm)
	if err != nil {
		t.Fatalf("BuildSignedResponse() error: %v", err)
	}
	if !strings.Contains(string(responseXML), "user-2") {
		t.Error("expected user ID in NameID when email is empty")
	}
}

// --- randomSAMLID test ---

func TestRandomSAMLID(t *testing.T) {
	id1, err := randomSAMLID()
	if err != nil {
		t.Fatal(err)
	}
	id2, _ := randomSAMLID()
	if id1 == id2 {
		t.Error("expected unique IDs")
	}
	if !strings.HasPrefix(id1, "_") {
		t.Errorf("SAML ID must start with underscore, got %q", id1)
	}
}

// --- HTTP handler tests ---

func newTestDeps(t *testing.T) RouterDeps {
	t.Helper()
	cm, err := NewCertManager()
	if err != nil {
		t.Fatal(err)
	}
	return RouterDeps{
		Flows:      memory.NewFlowStore(),
		Users:      memory.NewUserStore(),
		Sessions:   memory.NewSessionStore(),
		CertMgr:    cm,
		EntityID:   "http://localhost:8026",
		SSOURL:     "http://localhost:8026/saml/sso",
		SLOURL:     "http://localhost:8026/saml/slo",
		LoginURL:   "http://localhost:8025/login",
		SessionTTL: 1 * time.Hour,
	}
}

func TestMetadataHandler(t *testing.T) {
	dep := newTestDeps(t)
	r := NewRouter(dep)

	req := httptest.NewRequest(http.MethodGet, "/saml/metadata", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "samlmetadata") && !strings.Contains(ct, "xml") {
		t.Errorf("unexpected Content-Type: %q", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "EntityDescriptor") {
		t.Error("expected EntityDescriptor in metadata response")
	}
	if !strings.Contains(body, "SingleSignOnService") {
		t.Error("expected SingleSignOnService in metadata response")
	}
}

func TestCertHandler(t *testing.T) {
	dep := newTestDeps(t)
	r := NewRouter(dep)

	req := httptest.NewRequest(http.MethodGet, "/saml/cert", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "BEGIN CERTIFICATE") {
		t.Error("expected PEM certificate in response")
	}
}

func TestSSOHandler_NoRequest(t *testing.T) {
	dep := newTestDeps(t)
	r := NewRouter(dep)

	req := httptest.NewRequest(http.MethodGet, "/saml/sso", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (info page)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "SAML") {
		t.Error("expected SAML info page content")
	}
}

func TestSSOHandler_InitiatesFlow(t *testing.T) {
	dep := newTestDeps(t)
	r := NewRouter(dep)

	// Build a minimal base64-encoded AuthnRequest.
	xmlStr := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_flowtest" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" AssertionConsumerServiceURL="https://sp.example.com/acs"><saml:Issuer>https://sp.example.com</saml:Issuer></samlp:AuthnRequest>`
	encoded := base64.StdEncoding.EncodeToString([]byte(xmlStr))

	target := "/saml/sso?SAMLRequest=" + url.QueryEscape(encoded) + "&RelayState=relay123"
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want 302 redirect to login", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "/login") {
		t.Errorf("expected redirect to /login, got %q", loc)
	}
	if !strings.Contains(loc, "flow_id=") {
		t.Errorf("expected flow_id in redirect, got %q", loc)
	}

	// Verify flow was created.
	flows, err := dep.Flows.List()
	if err != nil {
		t.Fatal(err)
	}
	var samlFlows []domain.Flow
	for _, f := range flows {
		if f.Protocol == "saml" {
			samlFlows = append(samlFlows, f)
		}
	}
	if len(samlFlows) != 1 {
		t.Errorf("expected 1 saml flow, got %d", len(samlFlows))
	}
	if samlFlows[0].ClientID != "https://sp.example.com" {
		t.Errorf("ClientID = %q, want SP entity ID", samlFlows[0].ClientID)
	}
}

func TestSSOHandler_CompletesFlow(t *testing.T) {
	dep := newTestDeps(t)
	r := NewRouter(dep)

	// Create a user.
	user := domain.User{ID: "u1", Email: "bob@example.com", DisplayName: "Bob"}
	created, err := dep.Users.Create(user)
	if err != nil {
		t.Fatal(err)
	}

	// Create a completed SAML flow.
	flow := domain.Flow{
		ID:          "flow_samltest",
		State:       "complete",
		Protocol:    "saml",
		UserID:      created.ID,
		ClientID:    "https://sp.example.com",
		RedirectURI: "https://sp.example.com/acs",
		OAuthState:  "relay123|_flowtest",
		CreatedAt:   time.Now().UTC(),
		ExpiresAt:   time.Now().UTC().Add(30 * time.Minute),
	}
	createdFlow, err := dep.Flows.Create(flow)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/saml/sso?flow_id="+createdFlow.ID, nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (auto-submit form)", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "SAMLResponse") {
		t.Error("expected SAMLResponse in auto-submit form")
	}
	if !strings.Contains(body, "https://sp.example.com/acs") {
		t.Error("expected ACS URL in form action")
	}
	if !strings.Contains(body, "relay123") {
		t.Error("expected RelayState in form")
	}
}

func TestSSOFlowsHandler(t *testing.T) {
	dep := newTestDeps(t)
	r := NewRouter(dep)

	req := httptest.NewRequest(http.MethodGet, "/saml/flows", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

// --- ExclC14N tests ---

func TestExclC14N_Basic(t *testing.T) {
	input := `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_test"><saml:Issuer>https://idp.example.com</saml:Issuer></saml:Assertion>`
	out, err := ExclC14N([]byte(input))
	if err != nil {
		t.Fatalf("ExclC14N() error: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("expected non-empty output")
	}
	// Must not contain XML declaration.
	if strings.Contains(string(out), "<?xml") {
		t.Error("c14n output must not contain XML declaration")
	}
	// Must preserve element content.
	if !strings.Contains(string(out), "https://idp.example.com") {
		t.Error("expected issuer value in c14n output")
	}
}

func TestExclC14N_StripDeclaration(t *testing.T) {
	input := `<?xml version="1.0" encoding="UTF-8"?><root><child>text</child></root>`
	out, err := ExclC14N([]byte(input))
	if err != nil {
		t.Fatalf("ExclC14N() error: %v", err)
	}
	if strings.Contains(string(out), "<?xml") {
		t.Error("c14n must strip XML declaration")
	}
	if !strings.Contains(string(out), "<child>text</child>") {
		t.Error("expected child element in output")
	}
}

func TestExclC14N_AttributeEscaping(t *testing.T) {
	input := `<root attr="val&quot;ue"/>`
	out, err := ExclC14N([]byte(input))
	if err != nil {
		t.Fatalf("ExclC14N() error: %v", err)
	}
	// Self-closing must be expanded and attribute value preserved.
	if !strings.Contains(string(out), "</root>") {
		t.Error("expected explicit close tag")
	}
}

// --- LogoutRequest parsing ---

func TestParseLogoutRequest_Valid(t *testing.T) {
	xmlStr := `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_logoutid" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"><saml:Issuer>https://sp.example.com</saml:Issuer><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@example.com</saml:NameID></samlp:LogoutRequest>`
	encoded := base64.StdEncoding.EncodeToString([]byte(xmlStr))

	req, err := ParseLogoutRequest(encoded)
	if err != nil {
		t.Fatalf("ParseLogoutRequest() error: %v", err)
	}
	if req.ID != "_logoutid" {
		t.Errorf("ID = %q, want %q", req.ID, "_logoutid")
	}
	if req.NameID.Value != "alice@example.com" {
		t.Errorf("NameID = %q, want alice@example.com", req.NameID.Value)
	}
}

func TestParseLogoutRequest_MissingID(t *testing.T) {
	xmlStr := `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">sp</saml:Issuer></samlp:LogoutRequest>`
	encoded := base64.StdEncoding.EncodeToString([]byte(xmlStr))
	_, err := ParseLogoutRequest(encoded)
	if err == nil {
		t.Error("expected error for missing ID")
	}
}

// --- BuildLogoutResponse ---

func TestBuildLogoutResponse(t *testing.T) {
	cm, err := NewCertManager()
	if err != nil {
		t.Fatal(err)
	}
	out, err := BuildLogoutResponse("https://idp.example.com", "https://sp.example.com/slo", "_logoutid", cm)
	if err != nil {
		t.Fatalf("BuildLogoutResponse() error: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "LogoutResponse") {
		t.Error("expected LogoutResponse element")
	}
	if !strings.Contains(s, statusSuccess) {
		t.Error("expected success status")
	}
	if !strings.Contains(s, "ds:Signature") {
		t.Error("expected signature in logout response")
	}
}

// --- SLO handler tests ---

func TestSLOHandler_NoRequest(t *testing.T) {
	dep := newTestDeps(t)
	r := NewRouter(dep)

	req := httptest.NewRequest(http.MethodGet, "/saml/slo", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (info page)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "SLO") || !strings.Contains(rec.Body.String(), "saml/slo") {
		t.Error("expected SLO info page content")
	}
}

func TestSLOHandler_IdPInitiated(t *testing.T) {
	dep := newTestDeps(t)

	// Create a user and a session for them.
	user := domain.User{ID: "u-slo", Email: "slo@example.com"}
	created, err := dep.Users.Create(user)
	if err != nil {
		t.Fatal(err)
	}
	_, err = dep.Sessions.Create(domain.Session{
		ID:        "sess-slo",
		UserID:    created.ID,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	r := NewRouter(dep)
	req := httptest.NewRequest(http.MethodGet, "/saml/slo?user_id="+created.ID, nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), created.ID) {
		t.Error("expected user ID in confirmation page")
	}

	// Session should be gone.
	all, _ := dep.Sessions.List()
	for _, s := range all {
		if s.UserID == created.ID {
			t.Error("expected session to be invalidated")
		}
	}
}

func TestSLOHandler_SPInitiated(t *testing.T) {
	dep := newTestDeps(t)
	r := NewRouter(dep)

	xmlStr := `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_slo1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" Destination="http://localhost:8026/saml/slo"><saml:Issuer>https://sp.example.com</saml:Issuer><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@example.com</saml:NameID></samlp:LogoutRequest>`
	encoded := base64.StdEncoding.EncodeToString([]byte(xmlStr))

	target := "/saml/slo?SAMLRequest=" + url.QueryEscape(encoded) + "&RelayState=relay456"
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (auto-submit form)", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "SAMLResponse") {
		t.Error("expected SAMLResponse in logout response form")
	}
	if !strings.Contains(body, "relay456") {
		t.Error("expected RelayState in form")
	}
}

// --- Metadata includes SLO ---

func TestMetadataIncludesSLO(t *testing.T) {
	cm, err := NewCertManager()
	if err != nil {
		t.Fatal(err)
	}
	data, err := BuildMetadataWithSLO("https://idp.example.com", "https://idp.example.com/saml/sso", "https://idp.example.com/saml/slo", cm)
	if err != nil {
		t.Fatalf("BuildMetadataWithSLO() error: %v", err)
	}
	if !strings.Contains(string(data), "SingleLogoutService") {
		t.Error("expected SingleLogoutService in metadata")
	}
	if !strings.Contains(string(data), "saml/slo") {
		t.Error("expected SLO URL in metadata")
	}
}
