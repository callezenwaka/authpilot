package httpapi

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gorilla/mux"

	"furnace/server/internal/audit"
	"furnace/server/internal/domain"
	flowengine "furnace/server/internal/flow"
	"furnace/server/internal/store"
)

// webAuthnUser wraps domain.User to satisfy webauthn.User.
type webAuthnUser struct {
	u     domain.User
	creds []webauthn.Credential
}

func newWebAuthnUser(u domain.User) (webAuthnUser, error) {
	wu := webAuthnUser{u: u}
	if u.WebAuthnCredentials != "" {
		if err := json.Unmarshal([]byte(u.WebAuthnCredentials), &wu.creds); err != nil {
			return wu, fmt.Errorf("decode webauthn credentials: %w", err)
		}
	}
	return wu, nil
}

func (u webAuthnUser) WebAuthnID() []byte           { return []byte(u.u.ID) }
func (u webAuthnUser) WebAuthnName() string          { return u.u.Email }
func (u webAuthnUser) WebAuthnDisplayName() string   { return u.u.DisplayName }
func (u webAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// newWebAuthn creates a per-request webauthn.WebAuthn instance derived from the request host.
func newWebAuthn(r *http.Request) (*webauthn.WebAuthn, error) {
	host := r.Host
	if host == "" {
		host = "localhost"
	}
	rpID := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		rpID = h
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: "Furnace",
		RPOrigins:     []string{scheme + "://" + host},
	})
}

// webauthnBeginRegisterHandler handles GET /api/v1/flows/{id}/webauthn-begin-register.
// Returns PublicKeyCredentialCreationOptions JSON for navigator.credentials.create().
func webauthnBeginRegisterHandler(flows store.FlowStore, users store.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flowID := mux.Vars(r)["id"]
		flow, err := flows.GetByID(flowID)
		if err != nil {
			writeError(w, http.StatusNotFound, "not_found", "flow not found")
			return
		}
		if flow.State != string(flowengine.StateWebAuthnPending) {
			writeError(w, http.StatusConflict, "STATE_TRANSITION_INVALID", "flow is not in webauthn_pending state")
			return
		}
		user, err := users.GetByID(flow.UserID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "user_not_found", err.Error())
			return
		}
		wu, err := newWebAuthnUser(user)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "credential_decode_failed", err.Error())
			return
		}
		wa, err := newWebAuthn(r)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "webauthn_init_failed", err.Error())
			return
		}
		creation, session, err := wa.BeginRegistration(wu)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "begin_registration_failed", err.Error())
			return
		}
		sessionJSON, err := json.Marshal(session)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "session_marshal_failed", err.Error())
			return
		}
		flow.WebAuthnSession = string(sessionJSON)
		if _, err := flows.Update(flow); err != nil {
			writeError(w, http.StatusInternalServerError, "update_flow_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, creation)
	}
}

// webauthnFinishRegisterHandler handles POST /api/v1/flows/{id}/webauthn-finish-register.
// Validates the attestation and stores the new credential on the user.
func webauthnFinishRegisterHandler(flows store.FlowStore, users store.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flowID := mux.Vars(r)["id"]
		flow, err := flows.GetByID(flowID)
		if err != nil {
			writeError(w, http.StatusNotFound, "not_found", "flow not found")
			return
		}
		if flow.WebAuthnSession == "" {
			writeError(w, http.StatusConflict, "NO_SESSION", "no WebAuthn session; call webauthn-begin-register first")
			return
		}
		var session webauthn.SessionData
		if err := json.Unmarshal([]byte(flow.WebAuthnSession), &session); err != nil {
			writeError(w, http.StatusInternalServerError, "session_decode_failed", err.Error())
			return
		}
		user, err := users.GetByID(flow.UserID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "user_not_found", err.Error())
			return
		}
		wu, err := newWebAuthnUser(user)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "credential_decode_failed", err.Error())
			return
		}
		wa, err := newWebAuthn(r)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "webauthn_init_failed", err.Error())
			return
		}
		credential, err := wa.FinishRegistration(wu, session, r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "REGISTRATION_FAILED", fmt.Sprintf("passkey registration failed: %v", err))
			return
		}
		wu.creds = append(wu.creds, *credential)
		credsJSON, err := json.Marshal(wu.creds)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "credential_marshal_failed", err.Error())
			return
		}
		user.WebAuthnCredentials = string(credsJSON)
		if _, err := users.Update(user); err != nil {
			writeError(w, http.StatusInternalServerError, "update_user_failed", err.Error())
			return
		}
		flow.WebAuthnSession = ""
		_, _ = flows.Update(flow)
		writeJSON(w, http.StatusOK, map[string]string{"status": "registered"})
	}
}

// webauthnBeginHandler handles GET /api/v1/flows/{id}/webauthn-begin.
// Returns PublicKeyCredentialRequestOptions JSON for navigator.credentials.get().
func webauthnBeginHandler(flows store.FlowStore, users store.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flowID := mux.Vars(r)["id"]
		flow, err := flows.GetByID(flowID)
		if err != nil {
			writeError(w, http.StatusNotFound, "not_found", "flow not found")
			return
		}
		if flow.State != string(flowengine.StateWebAuthnPending) {
			writeError(w, http.StatusConflict, "STATE_TRANSITION_INVALID", "flow is not in webauthn_pending state")
			return
		}
		user, err := users.GetByID(flow.UserID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "user_not_found", err.Error())
			return
		}
		wu, err := newWebAuthnUser(user)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "credential_decode_failed", err.Error())
			return
		}
		wa, err := newWebAuthn(r)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "webauthn_init_failed", err.Error())
			return
		}
		assertion, session, err := wa.BeginLogin(wu)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "begin_login_failed", err.Error())
			return
		}
		sessionJSON, err := json.Marshal(session)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "session_marshal_failed", err.Error())
			return
		}
		flow.WebAuthnSession = string(sessionJSON)
		if _, err := flows.Update(flow); err != nil {
			writeError(w, http.StatusInternalServerError, "update_flow_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, assertion)
	}
}

// webauthnResponseHandler handles POST /api/v1/flows/{id}/webauthn-response.
// Verifies the authenticator assertion and advances the flow from webauthn_pending → mfa_approved.
func webauthnResponseHandler(flows store.FlowStore, users store.UserStore, as store.AuditStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flowID := mux.Vars(r)["id"]
		flow, err := flows.GetByID(flowID)
		if err != nil {
			writeError(w, http.StatusNotFound, "not_found", "flow not found")
			return
		}
		if flow.State != string(flowengine.StateWebAuthnPending) {
			writeError(w, http.StatusConflict, "STATE_TRANSITION_INVALID", "flow is not awaiting WebAuthn response")
			return
		}
		if flow.WebAuthnSession == "" {
			writeError(w, http.StatusConflict, "NO_SESSION", "no WebAuthn session; call webauthn-begin first")
			return
		}
		var session webauthn.SessionData
		if err := json.Unmarshal([]byte(flow.WebAuthnSession), &session); err != nil {
			writeError(w, http.StatusInternalServerError, "session_decode_failed", err.Error())
			return
		}
		user, err := users.GetByID(flow.UserID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "user_not_found", err.Error())
			return
		}
		wu, err := newWebAuthnUser(user)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "credential_decode_failed", err.Error())
			return
		}
		wa, err := newWebAuthn(r)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "webauthn_init_failed", err.Error())
			return
		}
		credential, err := wa.FinishLogin(wu, session, r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "ASSERTION_FAILED", fmt.Sprintf("passkey authentication failed: %v", err))
			return
		}
		// Update sign count to prevent replay attacks.
		for i, c := range wu.creds {
			if string(c.ID) == string(credential.ID) {
				wu.creds[i] = *credential
				break
			}
		}
		if credsJSON, err := json.Marshal(wu.creds); err == nil {
			user.WebAuthnCredentials = string(credsJSON)
			_, _ = users.Update(user)
		}
		if !flowengine.CanTransition(flowengine.StateWebAuthnPending, flowengine.StateMFAApproved) {
			writeError(w, http.StatusConflict, "STATE_TRANSITION_INVALID", "invalid flow transition")
			return
		}
		flow.State = string(flowengine.StateMFAApproved)
		flow.WebAuthnSession = ""
		updated, err := flows.Update(flow)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "update_flow_failed", err.Error())
			return
		}
		if u, err := users.GetByID(updated.UserID); err == nil {
			if flowengine.NormalizeScenario(updated.Scenario) != flowengine.ScenarioNormal {
				u.NextFlow = string(flowengine.ScenarioNormal)
				_, _ = users.Update(u)
			}
		}
		audit.Emit(as, audit.EventFlowComplete, updated.UserID, updated.ID, map[string]any{
			"protocol": updated.Protocol,
			"method":   "webauthn",
		})
		writeJSON(w, http.StatusOK, updated)
	}
}
