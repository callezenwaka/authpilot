package saml

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"furnace/server/internal/domain"
	"furnace/server/internal/store"
)

func newFlowID() string {
	return fmt.Sprintf("flow_%d", time.Now().UnixNano())
}

// RouterDeps holds dependencies for the SAML HTTP router.
type RouterDeps struct {
	Flows      store.FlowStore
	Users      store.UserStore
	Sessions   store.SessionStore
	CertMgr    *CertManager
	EntityID   string // e.g. "http://localhost:8026"
	SSOURL     string // e.g. "http://localhost:8026/saml/sso"
	SLOURL     string // e.g. "http://localhost:8026/saml/slo"
	LoginURL   string // e.g. "http://localhost:8025/login"
	SessionTTL time.Duration
}

// NewRouter returns an http.Handler for SAML IdP endpoints.
// It is intended to be mounted on the protocol server (":8026").
func NewRouter(dep RouterDeps) http.Handler {
	if dep.SessionTTL <= 0 {
		dep.SessionTTL = 1 * time.Hour
	}

	r := mux.NewRouter()
	r.HandleFunc("/saml/metadata", metadataHandler(dep)).Methods(http.MethodGet)
	r.HandleFunc("/saml/sso", ssoHandler(dep)).Methods(http.MethodGet, http.MethodPost)
	r.HandleFunc("/saml/slo", sloHandler(dep)).Methods(http.MethodGet, http.MethodPost)
	r.HandleFunc("/saml/cert", certHandler(dep)).Methods(http.MethodGet)

	// API endpoint: list active SAML flows (useful for admin/debug).
	r.HandleFunc("/saml/flows", samlFlowsHandler(dep)).Methods(http.MethodGet)

	return r
}

// metadataHandler serves the IdP metadata XML.
func metadataHandler(dep RouterDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := BuildMetadataWithSLO(dep.EntityID, dep.SSOURL, dep.SLOURL, dep.CertMgr)
		if err != nil {
			writeSAMLError(w, http.StatusInternalServerError, "metadata_error", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		_, _ = w.Write(data)
	}
}

// certHandler returns the PEM-encoded signing certificate for download.
func certHandler(dep RouterDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", `attachment; filename="furnace-idp.pem"`)
		_, _ = w.Write(dep.CertMgr.CertPEM())
	}
}

// ssoHandler handles SP-initiated SSO (HTTP-POST and HTTP-Redirect bindings).
//
// Flow:
//  1. SP sends AuthnRequest (POST: form field SAMLRequest, GET: query param SAMLRequest).
//  2. We parse the request, create a SAML flow, and redirect to /login.
//  3. After the user completes login, /login/complete redirects back here via
//     GET /saml/sso?flow_id=<id>.
//  4. We build a signed assertion and POST it to the SP's ACS.
func ssoHandler(dep RouterDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Step 3: returning from login with a completed flow.
		if flowID := r.URL.Query().Get("flow_id"); flowID != "" {
			completeSAMLSSO(w, r, dep, flowID)
			return
		}

		// Step 1: incoming AuthnRequest from SP.
		var rawRequest string
		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				writeSAMLError(w, http.StatusBadRequest, "parse_form", err.Error())
				return
			}
			rawRequest = r.FormValue("SAMLRequest")
		} else {
			rawRequest = r.URL.Query().Get("SAMLRequest")
		}

		if rawRequest == "" {
			// No SAMLRequest — show a plain info page for browser visitors.
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, samlInfoPage, dep.EntityID, dep.SSOURL, dep.EntityID, dep.EntityID)
			return
		}

		authnReq, err := ParseAuthnRequest(rawRequest)
		if err != nil {
			writeSAMLError(w, http.StatusBadRequest, "invalid_authn_request", err.Error())
			return
		}

		acs, err := acsFromRequest(authnReq, nil)
		if err != nil {
			writeSAMLError(w, http.StatusBadRequest, "missing_acs", err.Error())
			return
		}

		relayState := ""
		if r.Method == http.MethodPost {
			relayState = r.FormValue("RelayState")
		} else {
			relayState = r.URL.Query().Get("RelayState")
		}

		// Create a SAML flow to carry state through the login UX.
		flow := domain.Flow{
			ID:        newFlowID(),
			State:     "initiated",
			Protocol:  "saml",
			CreatedAt: time.Now().UTC(),
			ExpiresAt: time.Now().UTC().Add(30 * time.Minute),
			// Store SAML-specific fields in the OIDC fields we have available.
			// ClientID = SP EntityID, RedirectURI = ACS URL, OAuthState = RelayState + "|" + AuthnRequest ID
			ClientID:    authnReq.Issuer,
			RedirectURI: acs,
			OAuthState:  relayState + "|" + authnReq.ID,
		}

		created, err := dep.Flows.Create(flow)
		if err != nil {
			writeSAMLError(w, http.StatusInternalServerError, "flow_create_failed", err.Error())
			return
		}

		// Redirect to the login UI, which will redirect back to /saml/sso?flow_id=<id> on completion.
		callbackURL := dep.SSOURL + "?flow_id=" + created.ID
		loginURL := dep.LoginURL + "?flow_id=" + created.ID + "&redirect_uri=" + callbackURL
		http.Redirect(w, r, loginURL, http.StatusFound)
	}
}

// completeSAMLSSO is called after the user finishes the login flow.
// It retrieves the completed flow and POSTs a signed SAML response to the SP's ACS.
func completeSAMLSSO(w http.ResponseWriter, r *http.Request, dep RouterDeps, flowID string) {
	flow, err := dep.Flows.GetByID(flowID)
	if err != nil {
		writeSAMLError(w, http.StatusNotFound, "flow_not_found", "flow not found")
		return
	}

	if flow.State != "complete" {
		writeSAMLError(w, http.StatusConflict, "flow_not_complete", "flow has not completed login yet")
		return
	}

	user, err := dep.Users.GetByID(flow.UserID)
	if err != nil {
		writeSAMLError(w, http.StatusInternalServerError, "user_not_found", "authenticated user not found")
		return
	}

	acs := flow.RedirectURI
	parts := strings.SplitN(flow.OAuthState, "|", 2)
	relayState := ""
	inResponseTo := ""
	if len(parts) == 2 {
		relayState = parts[0]
		inResponseTo = parts[1]
	}

	cfg := AssertionConfig{
		IssuerEntityID: dep.EntityID,
		ACS:            acs,
		Audience:       flow.ClientID,
		InResponseTo:   inResponseTo,
		SessionTTL:     dep.SessionTTL,
	}

	responseXML, err := BuildSignedResponse(cfg, user, dep.CertMgr)
	if err != nil {
		writeSAMLError(w, http.StatusInternalServerError, "assertion_build_failed", err.Error())
		return
	}

	samlResponseB64 := base64.StdEncoding.EncodeToString(responseXML)

	// Record a session.
	now := time.Now().UTC()
	session := domain.Session{
		UserID:    user.ID,
		FlowID:    flow.ID,
		Protocol:  "saml",
		CreatedAt: now,
		ExpiresAt: now.Add(dep.SessionTTL),
		Events: []domain.SessionEvent{
			{Timestamp: now, Type: "token_issued"},
		},
	}
	_, _ = dep.Sessions.Create(session)

	// Serve an auto-submitting HTML form that POSTs to the SP ACS.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, samlPostForm, acs, samlResponseB64, relayState)
}

// sloHandler handles SP-initiated and IdP-initiated Single Logout.
//
// SP-initiated flow:
//  1. SP sends a LogoutRequest (GET: SAMLRequest query param, POST: form field).
//  2. We parse it, invalidate all sessions for the named user, and return a
//     signed LogoutResponse via auto-submit POST form to the SP's SLO return URL.
//
// IdP-initiated flow (GET /saml/slo?user_id=<id>):
//  1. Caller specifies a user_id to log out.
//  2. We invalidate all sessions for that user and return a confirmation page.
func sloHandler(dep RouterDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// IdP-initiated: ?user_id=<id>
		if uid := strings.TrimSpace(r.URL.Query().Get("user_id")); uid != "" {
			if err := invalidateUserSessions(dep.Sessions, uid); err != nil {
				writeSAMLError(w, http.StatusInternalServerError, "slo_failed", err.Error())
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, sloConfirmPage, uid)
			return
		}

		// SP-initiated: parse SAMLRequest.
		var rawRequest string
		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				writeSAMLError(w, http.StatusBadRequest, "parse_form", err.Error())
				return
			}
			rawRequest = r.FormValue("SAMLRequest")
		} else {
			rawRequest = r.URL.Query().Get("SAMLRequest")
		}

		if rawRequest == "" {
			// No request — show info page.
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, sloInfoPage, dep.SLOURL)
			return
		}

		logoutReq, err := ParseLogoutRequest(rawRequest)
		if err != nil {
			writeSAMLError(w, http.StatusBadRequest, "invalid_logout_request", err.Error())
			return
		}

		relayState := ""
		if r.Method == http.MethodPost {
			relayState = r.FormValue("RelayState")
		} else {
			relayState = r.URL.Query().Get("RelayState")
		}

		// Determine which user to log out from NameID.
		nameID := strings.TrimSpace(logoutReq.NameID.Value)

		// Find and invalidate sessions for this NameID (matched by user email or ID).
		_ = invalidateSessionsByNameID(dep.Sessions, dep.Users, nameID)

		// Build a signed LogoutResponse.
		// The response goes back to the SP's SLO endpoint (Destination in the request,
		// or fall back to the SP issuer entity — for dev we just echo back to SLOURL).
		destination := strings.TrimSpace(logoutReq.Destination)
		if destination == "" {
			destination = dep.SLOURL
		}

		responseXML, err := BuildLogoutResponse(dep.EntityID, destination, logoutReq.ID, dep.CertMgr)
		if err != nil {
			writeSAMLError(w, http.StatusInternalServerError, "logout_response_failed", err.Error())
			return
		}

		responseB64 := base64.StdEncoding.EncodeToString(responseXML)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, samlPostFormSLO, destination, responseB64, relayState)
	}
}

// invalidateUserSessions deletes all sessions belonging to userID.
func invalidateUserSessions(sessions store.SessionStore, userID string) error {
	all, err := sessions.List()
	if err != nil {
		return err
	}
	for _, s := range all {
		if s.UserID == userID {
			_ = sessions.Delete(s.ID)
		}
	}
	return nil
}

// invalidateSessionsByNameID finds sessions where user email or ID matches nameID.
func invalidateSessionsByNameID(sessions store.SessionStore, users store.UserStore, nameID string) error {
	all, err := sessions.List()
	if err != nil {
		return err
	}
	for _, s := range all {
		user, err := users.GetByID(s.UserID)
		if err != nil {
			continue
		}
		if user.ID == nameID || user.Email == nameID {
			_ = sessions.Delete(s.ID)
		}
	}
	return nil
}

// samlFlowsHandler returns SAML flows for admin/debug.
func samlFlowsHandler(dep RouterDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		all, err := dep.Flows.List()
		if err != nil {
			writeSAMLError(w, http.StatusInternalServerError, "list_failed", err.Error())
			return
		}
		var samlFlows []domain.Flow
		for _, f := range all {
			if f.Protocol == "saml" {
				samlFlows = append(samlFlows, f)
			}
		}
		if samlFlows == nil {
			samlFlows = []domain.Flow{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(samlFlows)
	}
}

func writeSAMLError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	})
}

// samlPostForm is the auto-submit HTML form sent to the browser to POST to the SP ACS.
const samlPostForm = `<!DOCTYPE html>
<html>
<head><title>Redirecting…</title></head>
<body>
<noscript>JavaScript is required to complete sign-in.</noscript>
<form method="POST" action="%s" id="samlForm">
  <input type="hidden" name="SAMLResponse" value="%s"/>
  <input type="hidden" name="RelayState" value="%s"/>
  <noscript><button type="submit">Continue</button></noscript>
</form>
<script>document.getElementById('samlForm').submit();</script>
</body>
</html>`

// samlPostFormSLO is the auto-submit form for LogoutResponse delivery.
const samlPostFormSLO = `<!DOCTYPE html>
<html>
<head><title>Signing out…</title></head>
<body>
<noscript>JavaScript is required to complete sign-out.</noscript>
<form method="POST" action="%s" id="sloForm">
  <input type="hidden" name="SAMLResponse" value="%s"/>
  <input type="hidden" name="RelayState" value="%s"/>
  <noscript><button type="submit">Continue</button></noscript>
</form>
<script>document.getElementById('sloForm').submit();</script>
</body>
</html>`

// sloConfirmPage is shown for IdP-initiated logout.
const sloConfirmPage = `<!DOCTYPE html>
<html>
<head><title>Signed out</title></head>
<body style="font-family:system-ui;max-width:600px;margin:48px auto;padding:0 24px">
<h2>Signed out</h2>
<p>All sessions for user <code>%s</code> have been invalidated.</p>
</body>
</html>`

// sloInfoPage is shown when /saml/slo is visited without a SAMLRequest.
const sloInfoPage = `<!DOCTYPE html>
<html>
<head><title>Furnace SAML SLO</title></head>
<body style="font-family:system-ui;max-width:600px;margin:48px auto;padding:0 24px">
<h2>Furnace — SAML Single Logout</h2>
<p>This is the SAML 2.0 SLO endpoint: <code>%s</code></p>
<p>Send a signed LogoutRequest here, or use <code>?user_id=&lt;id&gt;</code> for IdP-initiated logout.</p>
</body>
</html>`

// samlInfoPage is shown when /saml/sso is visited without a SAMLRequest.
const samlInfoPage = `<!DOCTYPE html>
<html>
<head><title>Furnace SAML IdP</title></head>
<body style="font-family:system-ui;max-width:600px;margin:48px auto;padding:0 24px">
<h2>Furnace — SAML Identity Provider</h2>
<p>This is the SAML 2.0 SSO endpoint. Configure your SP with:</p>
<ul>
  <li><b>IdP Entity ID:</b> <code>%s</code></li>
  <li><b>SSO URL:</b> <code>%s</code></li>
  <li><b>Metadata URL:</b> <code>%s/saml/metadata</code></li>
  <li><b>Signing Certificate:</b> <a href="%s/saml/cert">Download PEM</a></li>
</ul>
</body>
</html>`
