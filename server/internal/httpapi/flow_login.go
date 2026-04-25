package httpapi

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"furnace/server/internal/audit"
	"furnace/server/internal/domain"
	flowengine "furnace/server/internal/flow"
	"furnace/server/internal/store"
)

const defaultFlowTTL = 30 * time.Minute

type flowMutationRequest struct {
	UserID        string `json:"user_id"`
	Code          string `json:"code"`
	ExpectedState string `json:"expected_state"`
}

type loginViewData struct {
	FlowID               string
	Flow                 domain.Flow
	Users                []domain.User
	User                 domain.User
	Error                string
	HasError             bool
	HasWebAuthnCredential bool
}

var loginTemplate = template.Must(template.New("login").Parse(`<!doctype html>
<html>
<head>
<meta charset="utf-8"><title>Furnace Login</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='6' fill='%232563eb'/%3E%3Ctext x='7' y='24' font-size='20' font-weight='700' font-family='system-ui,sans-serif' fill='white'%3EF%3C/text%3E%3C/svg%3E">
<style>
  *,*::before,*::after{box-sizing:border-box}
  body{margin:0;background:#f5f6fa;font-family:system-ui,-apple-system,sans-serif;font-size:14px;color:#111827;display:flex;min-height:100vh;align-items:center;justify-content:center}
  .card{background:#fff;border:1px solid #e2e4ea;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.08);width:100%;max-width:440px;padding:32px}
  .logo{font-weight:700;font-size:18px;color:#1e293b;margin-bottom:24px;letter-spacing:.02em}.logo span{color:#2563eb}
  h1{margin:0 0 4px;font-size:1.25rem;font-weight:700}
  .sub{color:#6b7280;font-size:.875rem;margin-bottom:24px}
  .err{color:#dc2626;font-size:.875rem;margin-bottom:16px;padding:10px 12px;background:#fee2e2;border-radius:6px}
  .user-option{display:block;border:1px solid #e2e4ea;border-radius:6px;padding:10px 14px;margin-bottom:8px;cursor:pointer;transition:border-color .15s,background .15s}
  .user-option:hover{border-color:#2563eb;background:#f0f6ff}
  .user-option input{display:none}
  .user-option input:checked~.user-label{font-weight:600;color:#1d4ed8}
  .user-label{display:flex;flex-direction:column;gap:2px;pointer-events:none}
  .user-name{font-size:.9rem;font-weight:500}
  .user-meta{font-size:.78rem;color:#6b7280}
  .mfa-badge{display:inline-block;padding:1px 6px;border-radius:999px;font-size:.7rem;font-weight:600;background:#dbeafe;color:#1d4ed8;margin-left:4px}
  button{width:100%;margin-top:16px;padding:9px 18px;background:#2563eb;color:#fff;border:none;border-radius:6px;font-size:.95rem;font-weight:500;cursor:pointer;transition:background .15s}
  button:hover{background:#1d4ed8}
</style>
</head>
<body>
  <div class="card">
    <div class="logo">Fur<span>nace</span></div>
    <h1>Sign In</h1>
    <p class="sub">Select your account to continue</p>
    {{if .HasError}}<div class="err">{{.Error}}</div>{{end}}
    <form method="post" action="/login/select-user?flow_id={{.FlowID}}">
      {{range .Users}}
        <label class="user-option">
          <input type="radio" name="user_id" value="{{.ID}}" required>
          <div class="user-label">
            <span class="user-name">{{.DisplayName}}{{if .MFAMethod}}<span class="mfa-badge">{{.MFAMethod}}</span>{{end}}</span>
            <span class="user-meta">{{.Email}}</span>
          </div>
        </label>
      {{end}}
      <button type="submit">Continue</button>
    </form>
  </div>
</body>
</html>`))

var mfaTemplate = template.Must(template.New("mfa").Parse(`<!doctype html>
<html>
<head><meta charset="utf-8"><title>Furnace MFA</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='6' fill='%232563eb'/%3E%3Ctext x='7' y='24' font-size='20' font-weight='700' font-family='system-ui,sans-serif' fill='white'%3EF%3C/text%3E%3C/svg%3E">
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

  {{if eq .Flow.State "webauthn_pending"}}
    <p>{{if .HasWebAuthnCredential}}Authenticate with your registered passkey.{{else}}Register a passkey to continue.{{end}}</p>
    <p id="wa-err" style="color:#dc2626;font-size:13px;margin-bottom:8px"></p>
    <button id="wa-btn" class="btn" onclick="doWebAuthn()">
      {{if .HasWebAuthnCredential}}Authenticate with passkey{{else}}Register &amp; authenticate{{end}}
    </button>
    <a class="hub-link" href="/admin" target="_blank">→ Open admin panel</a>
    <script>
      function b64url(buf){return btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'')}
      function fromB64url(s){s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';return Uint8Array.from(atob(s),c=>c.charCodeAt(0)).buffer}
      function prepCreate(o){o.publicKey.challenge=fromB64url(o.publicKey.challenge);o.publicKey.user.id=fromB64url(o.publicKey.user.id);if(o.publicKey.excludeCredentials)o.publicKey.excludeCredentials=o.publicKey.excludeCredentials.map(c=>({...c,id:fromB64url(c.id)}));return o}
      function prepGet(o){o.publicKey.challenge=fromB64url(o.publicKey.challenge);if(o.publicKey.allowCredentials)o.publicKey.allowCredentials=o.publicKey.allowCredentials.map(c=>({...c,id:fromB64url(c.id)}));return o}
      function credJSON(c){const rsp={clientDataJSON:b64url(c.response.clientDataJSON)};if(c.response.attestationObject)rsp.attestationObject=b64url(c.response.attestationObject);if(c.response.authenticatorData)rsp.authenticatorData=b64url(c.response.authenticatorData);if(c.response.signature)rsp.signature=b64url(c.response.signature);if(c.response.userHandle)rsp.userHandle=b64url(c.response.userHandle);return{id:c.id,rawId:b64url(c.rawId),type:c.type,response:rsp}}
      const flowId="{{.FlowID}}";
      const hasCred={{if .HasWebAuthnCredential}}true{{else}}false{{end}};
      async function doWebAuthn(){
        const btn=document.getElementById('wa-btn'),err=document.getElementById('wa-err');
        btn.disabled=true;err.textContent='';
        try{
          if(!hasCred){
            btn.textContent='Registering passkey…';
            const ro=await fetch('/api/v1/flows/'+flowId+'/webauthn-begin-register').then(r=>r.json());
            const rc=await navigator.credentials.create(prepCreate(ro));
            const rr=await fetch('/api/v1/flows/'+flowId+'/webauthn-finish-register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(credJSON(rc))});
            if(!rr.ok){const e=await rr.json();throw new Error(e.error||'Registration failed')}
          }
          btn.textContent='Authenticating…';
          const ao=await fetch('/api/v1/flows/'+flowId+'/webauthn-begin').then(r=>r.json());
          const ac=await navigator.credentials.get(prepGet(ao));
          const ar=await fetch('/api/v1/flows/'+flowId+'/webauthn-response',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(credJSON(ac))});
          if(!ar.ok){const e=await ar.json();throw new Error(e.error||'Authentication failed')}
          window.location.href='/login/mfa?flow_id='+flowId;
        }catch(e){
          err.textContent=e.message;btn.disabled=false;
          btn.textContent=hasCred?'Authenticate with passkey':'Register & authenticate';
        }
      }
    </script>
  {{else if eq .User.MFAMethod "push"}}
    <div class="spinner"></div>
    <p class="waiting">Waiting for push approval on your device…</p>
    <a class="hub-link" href="/admin" target="_blank">→ Open notification hub</a>
    <script>
      const flowId = "{{.FlowID}}";
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
    <a class="hub-link" href="/admin" target="_blank">→ Open notification hub</a>
    <script>
      const flowId = "{{.FlowID}}";
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
    <a class="hub-link" href="/admin" target="_blank">→ Open notification hub</a>
  {{else}}
    <p>Enter the code from your authenticator app:</p>
    <form method="post" action="/login/mfa?flow_id={{.FlowID}}">
      <input type="text" name="code" placeholder="000000" autocomplete="one-time-code" required>
      <button type="submit">Verify</button>
    </form>
    <a class="hub-link" href="/admin" target="_blank">→ Open notification hub</a>
  {{end}}
</body>
</html>`))

var completeTemplate = template.Must(template.New("complete").Parse(`<!doctype html>
<html>
<head>
<meta charset="utf-8"><title>Furnace Complete</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='6' fill='%232563eb'/%3E%3Ctext x='7' y='24' font-size='20' font-weight='700' font-family='system-ui,sans-serif' fill='white'%3EF%3C/text%3E%3C/svg%3E">
<style>
  *,*::before,*::after{box-sizing:border-box}
  body{margin:0;background:#f5f6fa;font-family:system-ui,-apple-system,sans-serif;font-size:14px;color:#111827;display:flex;min-height:100vh;align-items:center;justify-content:center}
  .card{background:#fff;border:1px solid #e2e4ea;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.08);width:100%;max-width:440px;padding:32px}
  .logo{font-weight:700;font-size:18px;color:#1e293b;margin-bottom:24px;letter-spacing:.02em}.logo span{color:#2563eb}
  .icon{font-size:2.5rem;margin-bottom:12px}
  h1{margin:0 0 4px;font-size:1.25rem;font-weight:700}
  .sub{color:#6b7280;font-size:.875rem;margin-bottom:20px}
  .detail{background:#f5f6fa;border-radius:6px;padding:12px 14px;margin-bottom:16px;font-size:.85rem}
  .detail dt{color:#6b7280;font-weight:600;text-transform:uppercase;letter-spacing:.04em;font-size:.72rem;margin-bottom:2px}
  .detail dd{margin:0 0 10px;word-break:break-all}.detail dd:last-child{margin-bottom:0}
  .err{color:#dc2626;font-size:.875rem;padding:10px 12px;background:#fee2e2;border-radius:6px;margin-bottom:16px}
  a{color:#2563eb;text-decoration:none;font-size:.875rem}.a:hover{text-decoration:underline}
</style>
</head>
<body>
  <div class="card">
    <div class="logo">Fur<span>nace</span></div>
    {{if .Flow.Error}}
      <div class="icon">❌</div>
      <h1>Authentication Failed</h1>
      <p class="sub">The login flow could not be completed.</p>
      <div class="err">{{.Flow.Error}}</div>
    {{else}}
      <div class="icon">✅</div>
      <h1>Authentication Complete</h1>
      <p class="sub">The login flow finished successfully.</p>
    {{end}}
    <dl class="detail">
      <dt>State</dt><dd>{{.Flow.State}}</dd>
      {{if .Flow.UserID}}<dt>User</dt><dd>{{.User.DisplayName}} ({{.User.Email}})</dd>{{end}}
      <dt>Flow ID</dt><dd>{{.FlowID}}</dd>
    </dl>
    <a href="/login">← Start a new login</a>
  </div>
</body>
</html>`))

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
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = mfaTemplate.Execute(w, loginViewData{
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
