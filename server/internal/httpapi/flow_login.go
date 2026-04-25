package httpapi

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"furnace/server/internal/audit"
	"furnace/server/internal/domain"
	flowengine "furnace/server/internal/flow"
	"furnace/server/internal/store"
	"furnace/server/web"
)

const defaultFlowTTL = 30 * time.Minute

func newCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

type flowMutationRequest struct {
	UserID        string `json:"user_id"`
	Code          string `json:"code"`
	ExpectedState string `json:"expected_state"`
}

type loginViewData struct {
	FlowID                string
	Flow                  domain.Flow
	Users                 []domain.User
	User                  domain.User
	Error                 string
	HasError              bool
	HasWebAuthnCredential bool
	CSRFToken             string
}

func listFlowsHandler(flows store.FlowStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		result, err := flows.List()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "list_flows_failed", err.Error())
			return
		}
		if result == nil {
			result = []domain.Flow{}
		}
		writeJSON(w, http.StatusOK, result)
	}
}

func createFlowHandler(flows store.FlowStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		protocol := strings.TrimSpace(r.URL.Query().Get("protocol"))
		if protocol == "" {
			protocol = "oidc"
		}
		now := time.Now().UTC()
		flow := domain.Flow{
			ID:        fmt.Sprintf("flow_%d", now.UnixNano()),
			State:     string(flowengine.StateInitiated),
			Scenario:  string(flowengine.ScenarioNormal),
			Protocol:  protocol,
			CreatedAt: now,
			ExpiresAt: now.Add(defaultFlowTTL),
		}
		created, err := flows.Create(flow)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "create_flow_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, created)
	}
}

func getFlowHandler(flows store.FlowStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flowID := mux.Vars(r)["id"]
		flow, err := getAndAutoAdvanceFlow(flows, flowID)
		if err != nil {
			if err == store.ErrNotFound {
				writeError(w, http.StatusNotFound, "not_found", "flow not found", map[string]any{"flow_id": flowID})
				return
			}
			writeError(w, http.StatusInternalServerError, "get_flow_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, flow)
	}
}

func selectUserFlowHandler(flows store.FlowStore, users store.UserStore, as store.AuditStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flowID := mux.Vars(r)["id"]
		req, err := decodeFlowMutationRequest(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
			return
		}
		updated, status, code, msg := applySelectUser(flows, users, flowID, req.UserID, req.ExpectedState)
		if status != 0 {
			writeError(w, status, code, msg)
			return
		}
		emitFlowStateAudit(as, updated)
		writeJSON(w, http.StatusOK, updated)
	}
}

func verifyMFAFlowHandler(flows store.FlowStore, users store.UserStore, as store.AuditStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flowID := mux.Vars(r)["id"]
		req, err := decodeFlowMutationRequest(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
			return
		}
		updated, status, code, msg := applyVerifyMFA(flows, users, flowID, req.Code, req.ExpectedState)
		if status != 0 {
			writeError(w, status, code, msg)
			return
		}
		emitFlowStateAudit(as, updated)
		writeJSON(w, http.StatusOK, updated)
	}
}

func approveFlowHandler(flows store.FlowStore, users store.UserStore, as store.AuditStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flowID := mux.Vars(r)["id"]
		req, err := decodeFlowMutationRequest(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
			return
		}
		flow, status, code, msg := approveOrDenyFlow(flows, users, flowID, true, req.ExpectedState)
		if status != 0 {
			writeError(w, status, code, msg)
			return
		}
		emitFlowStateAudit(as, flow)
		writeJSON(w, http.StatusOK, flow)
	}
}

func denyFlowHandler(flows store.FlowStore, as store.AuditStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flowID := mux.Vars(r)["id"]
		req, err := decodeFlowMutationRequest(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
			return
		}
		flow, status, code, msg := approveOrDenyFlow(flows, nil, flowID, false, req.ExpectedState)
		if status != 0 {
			writeError(w, status, code, msg)
			return
		}
		emitFlowStateAudit(as, flow)
		writeJSON(w, http.StatusOK, flow)
	}
}

func loginPageHandler(flows store.FlowStore, users store.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flowID := strings.TrimSpace(r.URL.Query().Get("flow_id"))
		if flowID == "" {
			now := time.Now().UTC()
			created, err := flows.Create(domain.Flow{
				ID:        fmt.Sprintf("flow_%d", now.UnixNano()),
				State:     string(flowengine.StateInitiated),
				Scenario:  string(flowengine.ScenarioNormal),
				Protocol:  "oidc",
				CreatedAt: now,
				ExpiresAt: now.Add(defaultFlowTTL),
			})
			if err != nil {
				writeError(w, http.StatusInternalServerError, "create_flow_failed", err.Error())
				return
			}
			http.Redirect(w, r, "/login?flow_id="+created.ID, http.StatusFound)
			return
		}

		flow, err := getAndAutoAdvanceFlow(flows, flowID)
		if err != nil {
			writeError(w, http.StatusNotFound, "not_found", "flow not found")
			return
		}
		userList, err := users.List()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "list_users_failed", err.Error())
			return
		}
		csrfToken, err := newCSRFToken()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "csrf_failed", "could not generate CSRF token")
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "furnace_csrf",
			Value:    csrfToken,
			Path:     "/login",
			SameSite: http.SameSiteStrictMode,
			HttpOnly: true,
		})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		tmpl, err := web.ParseTemplate("login.html")
		if err != nil {
			http.Error(w, "template unavailable", http.StatusInternalServerError)
			return
		}
		_ = tmpl.Execute(w, loginViewData{FlowID: flowID, Flow: flow, Users: userList, CSRFToken: csrfToken})
	}
}

func loginSelectUserHandler(flows store.FlowStore, users store.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_form", err.Error())
			return
		}
		// CSRF double-submit cookie check.
		cookie, cookieErr := r.Cookie("furnace_csrf")
		formToken := r.FormValue("csrf_token")
		if cookieErr != nil || formToken == "" ||
			subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(formToken)) != 1 {
			writeError(w, http.StatusForbidden, "CSRF_INVALID", "invalid or missing CSRF token")
			return
		}
		flowID := strings.TrimSpace(r.URL.Query().Get("flow_id"))
		userID := strings.TrimSpace(r.FormValue("user_id"))
		updated, status, _, msg := applySelectUser(flows, users, flowID, userID, "")
		if status != 0 {
			flow, _ := flows.GetByID(flowID)
			userList, _ := users.List()
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			tmpl, err := web.ParseTemplate("login.html")
			if err != nil {
				http.Error(w, "template unavailable", http.StatusInternalServerError)
				return
			}
			_ = tmpl.Execute(w, loginViewData{FlowID: flowID, Flow: flow, Users: userList, Error: msg, HasError: true})
			return
		}
		switch updated.State {
		case string(flowengine.StateMFAPending), string(flowengine.StateWebAuthnPending), string(flowengine.StateMFAApproved):
			http.Redirect(w, r, "/login/mfa?flow_id="+flowID, http.StatusFound)
		default:
			http.Redirect(w, r, "/login/complete?flow_id="+flowID, http.StatusFound)
		}
	}
}

func loginMFAHandler(flows store.FlowStore, users store.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flowID := strings.TrimSpace(r.URL.Query().Get("flow_id"))
		flow, err := getAndAutoAdvanceFlow(flows, flowID)
		if err != nil {
			writeError(w, http.StatusNotFound, "not_found", "flow not found")
			return
		}
		if flow.State == string(flowengine.StateMFAApproved) {
			if completed, ok := moveToComplete(flows, flow); ok {
				flow = completed
			}
		}
		if flow.State == string(flowengine.StateComplete) || flow.State == string(flowengine.StateError) {
			http.Redirect(w, r, "/login/complete?flow_id="+flowID, http.StatusFound)
			return
		}
		user, _ := users.GetByID(flow.UserID)
		tmpl, err := web.ParseTemplate("mfa.html")
		if err != nil {
			http.Error(w, "template unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = tmpl.Execute(w, loginViewData{
			FlowID:                flowID,
			Flow:                  flow,
			User:                  user,
			HasWebAuthnCredential: user.WebAuthnCredentials != "",
		})
	}
}

func loginMFASubmitHandler(flows store.FlowStore, users store.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_form", err.Error())
			return
		}
		flowID := strings.TrimSpace(r.URL.Query().Get("flow_id"))
		code := strings.TrimSpace(r.FormValue("code"))
		_, status, _, msg := applyVerifyMFA(flows, users, flowID, code, "")
		if status != 0 {
			flow, _ := flows.GetByID(flowID)
			user, _ := users.GetByID(flow.UserID)
			tmpl, err := web.ParseTemplate("mfa.html")
			if err != nil {
				http.Error(w, "template unavailable", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_ = tmpl.Execute(w, loginViewData{FlowID: flowID, Flow: flow, User: user, Error: msg, HasError: true})
			return
		}
		http.Redirect(w, r, "/login/mfa?flow_id="+flowID, http.StatusFound)
	}
}

func loginCompleteHandler(flows store.FlowStore, users store.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flowID := strings.TrimSpace(r.URL.Query().Get("flow_id"))
		flow, err := flows.GetByID(flowID)
		if err != nil {
			writeError(w, http.StatusNotFound, "not_found", "flow not found")
			return
		}
		user, _ := users.GetByID(flow.UserID)
		tmpl, err := web.ParseTemplate("complete.html")
		if err != nil {
			http.Error(w, "template unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = tmpl.Execute(w, loginViewData{FlowID: flowID, Flow: flow, User: user})
	}
}

func decodeFlowMutationRequest(r *http.Request) (flowMutationRequest, error) {
	if r.Body == nil {
		return flowMutationRequest{}, nil
	}
	defer r.Body.Close()
	var req flowMutationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if strings.Contains(err.Error(), "EOF") {
			return flowMutationRequest{}, nil
		}
		return flowMutationRequest{}, err
	}
	return req, nil
}

func applySelectUser(flows store.FlowStore, users store.UserStore, flowID, userID, expectedState string) (domain.Flow, int, string, string) {
	if flowID == "" || userID == "" {
		return domain.Flow{}, http.StatusBadRequest, "validation_error", "flow_id and user_id are required"
	}

	flow, err := flows.GetByID(flowID)
	if err != nil {
		return domain.Flow{}, http.StatusNotFound, "not_found", "flow not found"
	}
	if expectedState != "" && flow.State != expectedState {
		return domain.Flow{}, http.StatusConflict, "STATE_TRANSITION_INVALID", "current state does not match expected_state"
	}
	if !flowengine.CanTransition(flowengine.State(flow.State), flowengine.StateUserPicked) {
		return domain.Flow{}, http.StatusConflict, "STATE_TRANSITION_INVALID", "invalid flow transition"
	}

	user, err := users.GetByID(userID)
	if err != nil {
		return domain.Flow{}, http.StatusNotFound, "not_found", "user not found"
	}

	flow.UserID = userID
	flow.State = string(flowengine.StateUserPicked)
	flow.Scenario = string(flowengine.NormalizeScenario(user.NextFlow))
	flow.Error = ""

	scenario := flowengine.NormalizeScenario(flow.Scenario)
	if scenario == flowengine.ScenarioAccountLocked {
		if !flowengine.CanTransition(flowengine.State(flow.State), flowengine.StateError) {
			return domain.Flow{}, http.StatusConflict, "STATE_TRANSITION_INVALID", "invalid flow transition"
		}
		flow.State = string(flowengine.StateError)
		flow.Error = "account locked"
		markTerminal(&flow)
		updated, err := flows.Update(flow)
		if err != nil {
			return domain.Flow{}, http.StatusInternalServerError, "update_flow_failed", err.Error()
		}
		return updated, 0, "", ""
	}

	if flowengine.RequiresMFA(user.MFAMethod) {
		nextState := flowengine.StateMFAPending
		if flowengine.IsWebAuthn(user.MFAMethod) {
			nextState = flowengine.StateWebAuthnPending
		}
		if !flowengine.CanTransition(flowengine.State(flow.State), nextState) {
			return domain.Flow{}, http.StatusConflict, "STATE_TRANSITION_INVALID", "invalid flow transition"
		}
		flow.State = string(nextState)
		updated, err := flows.Update(flow)
		if err != nil {
			return domain.Flow{}, http.StatusInternalServerError, "update_flow_failed", err.Error()
		}
		return updated, 0, "", ""
	}

	if !flowengine.CanTransition(flowengine.State(flow.State), flowengine.StateComplete) {
		return domain.Flow{}, http.StatusConflict, "STATE_TRANSITION_INVALID", "invalid flow transition"
	}
	flow.State = string(flowengine.StateComplete)
	markTerminal(&flow)
	if scenario != flowengine.ScenarioNormal {
		user.NextFlow = string(flowengine.ScenarioNormal)
		_, _ = users.Update(user)
	}
	updated, err := flows.Update(flow)
	if err != nil {
		return domain.Flow{}, http.StatusInternalServerError, "update_flow_failed", err.Error()
	}
	return updated, 0, "", ""
}

func applyVerifyMFA(flows store.FlowStore, users store.UserStore, flowID, code, expectedState string) (domain.Flow, int, string, string) {
	if flowID == "" {
		return domain.Flow{}, http.StatusBadRequest, "validation_error", "flow_id is required"
	}
	flow, err := flows.GetByID(flowID)
	if err != nil {
		return domain.Flow{}, http.StatusNotFound, "not_found", "flow not found"
	}
	if expectedState != "" && flow.State != expectedState {
		return domain.Flow{}, http.StatusConflict, "STATE_TRANSITION_INVALID", "current state does not match expected_state"
	}
	if flow.State != string(flowengine.StateMFAPending) {
		return domain.Flow{}, http.StatusConflict, "STATE_TRANSITION_INVALID", "flow is not awaiting MFA"
	}

	flow.Attempts++
	scenario := flowengine.NormalizeScenario(flow.Scenario)
	if scenario == flowengine.ScenarioMFAFail && flow.Attempts == 1 {
		if _, err := flows.Update(flow); err != nil {
			return domain.Flow{}, http.StatusInternalServerError, "update_flow_failed", err.Error()
		}
		return domain.Flow{}, http.StatusUnauthorized, "mfa_code_invalid", "invalid MFA code"
	}
	if strings.TrimSpace(code) == "" {
		if _, err := flows.Update(flow); err != nil {
			return domain.Flow{}, http.StatusInternalServerError, "update_flow_failed", err.Error()
		}
		return domain.Flow{}, http.StatusBadRequest, "validation_error", "code is required"
	}
	if !flowengine.CanTransition(flowengine.State(flow.State), flowengine.StateMFAApproved) {
		return domain.Flow{}, http.StatusConflict, "STATE_TRANSITION_INVALID", "invalid flow transition"
	}
	flow.State = string(flowengine.StateMFAApproved)
	updated, err := flows.Update(flow)
	if err != nil {
		return domain.Flow{}, http.StatusInternalServerError, "update_flow_failed", err.Error()
	}
	if user, err := users.GetByID(updated.UserID); err == nil && scenario != flowengine.ScenarioNormal {
		user.NextFlow = string(flowengine.ScenarioNormal)
		_, _ = users.Update(user)
	}
	return updated, 0, "", ""
}


func approveOrDenyFlow(flows store.FlowStore, users store.UserStore, flowID string, approve bool, expectedState string) (domain.Flow, int, string, string) {
	flow, err := flows.GetByID(flowID)
	if err != nil {
		return domain.Flow{}, http.StatusNotFound, "not_found", "flow not found"
	}
	if expectedState != "" && flow.State != expectedState {
		return domain.Flow{}, http.StatusConflict, "STATE_TRANSITION_INVALID", "current state does not match expected_state"
	}
	if flow.State != string(flowengine.StateMFAPending) {
		return domain.Flow{}, http.StatusConflict, "STATE_TRANSITION_INVALID", "flow is not awaiting MFA"
	}

	if approve {
		if flowengine.NormalizeScenario(flow.Scenario) == flowengine.ScenarioSlowMFA && time.Since(flow.CreatedAt) < 10*time.Second {
			return flow, http.StatusAccepted, "mfa_pending", "waiting for slow_mfa delay"
		}
		if !flowengine.CanTransition(flowengine.State(flow.State), flowengine.StateMFAApproved) {
			return domain.Flow{}, http.StatusConflict, "STATE_TRANSITION_INVALID", "invalid flow transition"
		}
		flow.State = string(flowengine.StateMFAApproved)
	} else {
		if !flowengine.CanTransition(flowengine.State(flow.State), flowengine.StateMFADenied) {
			return domain.Flow{}, http.StatusConflict, "STATE_TRANSITION_INVALID", "invalid flow transition"
		}
		flow.State = string(flowengine.StateMFADenied)
		markTerminal(&flow)
	}

	updated, err := flows.Update(flow)
	if err != nil {
		return domain.Flow{}, http.StatusInternalServerError, "update_flow_failed", err.Error()
	}
	if approve && users != nil {
		if user, err := users.GetByID(updated.UserID); err == nil && flowengine.NormalizeScenario(updated.Scenario) != flowengine.ScenarioNormal {
			user.NextFlow = string(flowengine.ScenarioNormal)
			_, _ = users.Update(user)
		}
	}
	return updated, 0, "", ""
}

// markTerminal stamps CompletedAt on the flow when it enters a terminal state.
func markTerminal(flow *domain.Flow) {
	switch flowengine.State(flow.State) {
	case flowengine.StateComplete, flowengine.StateMFADenied, flowengine.StateError:
		if flow.CompletedAt == nil {
			now := time.Now().UTC()
			flow.CompletedAt = &now
		}
	}
}

func getAndAutoAdvanceFlow(flows store.FlowStore, flowID string) (domain.Flow, error) {
	flow, err := flows.GetByID(flowID)
	if err != nil {
		return domain.Flow{}, err
	}
	if flow.State == string(flowengine.StateMFAPending) && flowengine.NormalizeScenario(flow.Scenario) == flowengine.ScenarioSlowMFA {
		if time.Since(flow.CreatedAt) >= 10*time.Second {
			if flowengine.CanTransition(flowengine.State(flow.State), flowengine.StateMFAApproved) {
				flow.State = string(flowengine.StateMFAApproved)
				updated, updateErr := flows.Update(flow)
				if updateErr == nil {
					flow = updated
				}
			}
		}
	}
	return flow, nil
}

// emitFlowStateAudit fires an audit event for terminal and key flow states.
func emitFlowStateAudit(as store.AuditStore, flow domain.Flow) {
	var eventType string
	switch flowengine.State(flow.State) {
	case flowengine.StateComplete:
		eventType = audit.EventFlowComplete
	case flowengine.StateMFADenied:
		eventType = audit.EventFlowDenied
	case flowengine.StateError:
		eventType = audit.EventFlowError
	default:
		return
	}
	audit.Emit(as, eventType, flow.UserID, flow.ID, map[string]any{
		"protocol": flow.Protocol,
		"scenario": flow.Scenario,
	})
}

func moveToComplete(flows store.FlowStore, flow domain.Flow) (domain.Flow, bool) {
	if !flowengine.CanTransition(flowengine.State(flow.State), flowengine.StateComplete) {
		return flow, false
	}
	flow.State = string(flowengine.StateComplete)
	markTerminal(&flow)
	updated, err := flows.Update(flow)
	if err != nil {
		return flow, false
	}
	return updated, true
}
