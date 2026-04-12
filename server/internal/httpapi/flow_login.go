package httpapi

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"authpilot/server/internal/domain"
	flowengine "authpilot/server/internal/flow"
	"authpilot/server/internal/store"
)

const defaultFlowTTL = 30 * time.Minute

type flowMutationRequest struct {
	UserID        string `json:"user_id"`
	Code          string `json:"code"`
	ExpectedState string `json:"expected_state"`
}

type loginViewData struct {
	FlowID   string
	Flow     domain.Flow
	Users    []domain.User
	User     domain.User
	Error    string
	HasError bool
}

var loginTemplate = template.Must(template.New("login").Parse(`<!doctype html>
<html>
<head><meta charset="utf-8"><title>Authpilot Login</title></head>
<body>
  <h1>Sign In</h1>
  <p>Flow ID: {{.FlowID}}</p>
  {{if .HasError}}<p style="color:#b00">{{.Error}}</p>{{end}}
  <form method="post" action="/login/select-user?flow_id={{.FlowID}}">
    {{range .Users}}
      <label style="display:block;margin:8px 0;">
        <input type="radio" name="user_id" value="{{.ID}}" required>
        {{.DisplayName}} ({{.Email}}) - MFA: {{.MFAMethod}}
      </label>
    {{end}}
    <button type="submit">Continue</button>
  </form>
</body>
</html>`))

var mfaTemplate = template.Must(template.New("mfa").Parse(`<!doctype html>
<html>
<head><meta charset="utf-8"><title>Authpilot MFA</title>
<style>
  body{font-family:system-ui,sans-serif;max-width:440px;margin:60px auto;padding:0 20px;color:#111}
  h1{font-size:1.4rem;margin-bottom:4px}
  .sub{color:#6b7280;font-size:.9rem;margin-bottom:24px}
  .hub-link{display:inline-block;margin-top:16px;font-size:.85rem;color:#2563eb;text-decoration:none}
  .hub-link:hover{text-decoration:underline}
  input[type=text]{width:100%;padding:8px 10px;border:1px solid #d1d5db;border-radius:6px;font-size:1rem;margin-bottom:12px}
  button{padding:8px 18px;background:#2563eb;color:#fff;border:none;border-radius:6px;font-size:.95rem;cursor:pointer}
  button:hover{background:#1d4ed8}
  .err{color:#dc2626;margin-bottom:12px;font-size:.9rem}
  .spinner{width:32px;height:32px;border:3px solid #e2e4ea;border-top-color:#2563eb;border-radius:50%;animation:spin .8s linear infinite;margin-bottom:12px}
  @keyframes spin{to{rotate:360deg}}
  .waiting{color:#6b7280;font-size:.95rem}
</style>
</head>
<body>
  <h1>Multi-Factor Authentication</h1>
  <p class="sub">{{.User.DisplayName}} ({{.User.Email}})</p>
  {{if .HasError}}<p class="err">{{.Error}}</p>{{end}}

  {{if eq .User.MFAMethod "push"}}
    <div class="spinner"></div>
    <p class="waiting">Waiting for push approval on your device…</p>
    <a class="hub-link" href="/notify" target="_blank">→ Open approval screen</a>
    <script>
      const flowId = {{printf "%q" .FlowID}};
      setInterval(async () => {
        const res = await fetch('/api/v1/flows/' + flowId);
        if (!res.ok) return;
        const flow = await res.json();
        if (flow.state === 'mfa_approved' || flow.state === 'complete') {
          window.location.href = '/login/mfa?flow_id=' + flowId;
        }
      }, 2000);
    </script>
  {{else if eq .User.MFAMethod "magic_link"}}
    <p>We sent a sign-in link to <strong>{{.User.Email}}</strong>.</p>
    <p class="waiting">Click the link in your email to continue.</p>
    <a class="hub-link" href="/notify" target="_blank">→ View email in notification hub</a>
    <script>
      const flowId = {{printf "%q" .FlowID}};
      setInterval(async () => {
        const res = await fetch('/api/v1/flows/' + flowId);
        if (!res.ok) return;
        const flow = await res.json();
        if (flow.state === 'mfa_approved' || flow.state === 'complete') {
          window.location.href = '/login/mfa?flow_id=' + flowId;
        }
      }, 2000);
    </script>
  {{else if eq .User.MFAMethod "sms"}}
    <p>Enter the code sent to {{.User.PhoneNumber}}:</p>
    <form method="post" action="/login/mfa?flow_id={{.FlowID}}">
      <input type="text" name="code" placeholder="000000" autocomplete="one-time-code" required>
      <button type="submit">Verify</button>
    </form>
    <a class="hub-link" href="/notify" target="_blank">→ View SMS in notification hub</a>
  {{else}}
    <p>Enter the code from your authenticator app:</p>
    <form method="post" action="/login/mfa?flow_id={{.FlowID}}">
      <input type="text" name="code" placeholder="000000" autocomplete="one-time-code" required>
      <button type="submit">Verify</button>
    </form>
    <a class="hub-link" href="/notify" target="_blank">→ View code in notification hub</a>
  {{end}}
</body>
</html>`))

var completeTemplate = template.Must(template.New("complete").Parse(`<!doctype html>
<html>
<head><meta charset="utf-8"><title>Authpilot Complete</title></head>
<body>
  <h1>Flow Result</h1>
  <p>Flow ID: {{.FlowID}}</p>
  <p>State: {{.Flow.State}}</p>
  {{if .Flow.UserID}}<p>User: {{.User.DisplayName}} ({{.User.Email}})</p>{{end}}
  {{if .Flow.Error}}<p style="color:#b00">Error: {{.Flow.Error}}</p>{{end}}
  <p><a href="/login?flow_id={{.FlowID}}">Back to login</a></p>
</body>
</html>`))

func listFlowsHandler(flows store.FlowStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		result, err := flows.List()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "list_flows_failed", err.Error())
			return
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
				writeError(w, http.StatusNotFound, "not_found", "flow not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "get_flow_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, flow)
	}
}

func selectUserFlowHandler(flows store.FlowStore, users store.UserStore) http.HandlerFunc {
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
		writeJSON(w, http.StatusOK, updated)
	}
}

func verifyMFAFlowHandler(flows store.FlowStore, users store.UserStore) http.HandlerFunc {
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
		writeJSON(w, http.StatusOK, updated)
	}
}

func approveFlowHandler(flows store.FlowStore, users store.UserStore) http.HandlerFunc {
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
		writeJSON(w, http.StatusOK, flow)
	}
}

func denyFlowHandler(flows store.FlowStore) http.HandlerFunc {
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
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = loginTemplate.Execute(w, loginViewData{FlowID: flowID, Flow: flow, Users: userList})
	}
}

func loginSelectUserHandler(flows store.FlowStore, users store.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_form", err.Error())
			return
		}
		flowID := strings.TrimSpace(r.URL.Query().Get("flow_id"))
		userID := strings.TrimSpace(r.FormValue("user_id"))
		updated, status, _, msg := applySelectUser(flows, users, flowID, userID, "")
		if status != 0 {
			flow, _ := flows.GetByID(flowID)
			userList, _ := users.List()
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_ = loginTemplate.Execute(w, loginViewData{FlowID: flowID, Flow: flow, Users: userList, Error: msg, HasError: true})
			return
		}
		switch updated.State {
		case string(flowengine.StateMFAPending), string(flowengine.StateMFAApproved):
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
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = mfaTemplate.Execute(w, loginViewData{FlowID: flowID, Flow: flow, User: user})
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
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_ = mfaTemplate.Execute(w, loginViewData{FlowID: flowID, Flow: flow, User: user, Error: msg, HasError: true})
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
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = completeTemplate.Execute(w, loginViewData{FlowID: flowID, Flow: flow, User: user})
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
		if !flowengine.CanTransition(flowengine.State(flow.State), flowengine.StateMFAPending) {
			return domain.Flow{}, http.StatusConflict, "STATE_TRANSITION_INVALID", "invalid flow transition"
		}
		flow.State = string(flowengine.StateMFAPending)
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
