package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"authpilot/server/internal/audit"
	"authpilot/server/internal/domain"
	"authpilot/server/internal/export"
	"authpilot/server/internal/notify"
	"authpilot/server/internal/store"
)

// MintedTokens is the response payload for POST /api/v1/tokens/mint.
type MintedTokens struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// TokenMinter issues tokens directly for a given user, bypassing the OAuth
// flow. Used by POST /api/v1/tokens/mint.
// Implemented by an adapter in app.go that wraps oidc.Issuer.
type TokenMinter interface {
	MintForUser(user domain.User, clientID string, scopes []string, expiresIn int) (MintedTokens, error)
}

// TokenTTLs holds the mutable token lifetime settings for PATCH /api/v1/config.
type TokenTTLs struct {
	AccessTokenTTL  *int `json:"access_token_ttl"`  // seconds
	IDTokenTTL      *int `json:"id_token_ttl"`       // seconds
	RefreshTokenTTL *int `json:"refresh_token_ttl"`  // seconds
}

// ConfigPatcher applies runtime-safe configuration changes.
// Implemented by an adapter in app.go that wraps oidc.Issuer.
type ConfigPatcher interface {
	GetTokenTTLs() TokenTTLs
	SetTokenTTLs(TokenTTLs) error
}

type Dependencies struct {
	Users           store.UserStore
	Groups          store.GroupStore
	Flows           store.FlowStore
	Sessions        store.SessionStore
	Audit           store.AuditStore  // nil = audit disabled
	AdminStaticDir  string
	NotifyStaticDir string
	APIKey          string       // empty = local dev mode (no auth required)
	SCIMKey         string       // separate credential for /scim/v2; falls back to APIKey when empty
	BaseURL         string       // e.g. "http://localhost:8025" — used for magic link URLs
	RateLimit       int          // requests per minute per IP; 0 = disabled
	SCIMRouter      http.Handler  // mounted at /scim/v2; nil = disabled
	TokenMinter     TokenMinter   // nil = /tokens/mint endpoint returns 501
	ConfigPatcher   ConfigPatcher // nil = /config PATCH returns 501
}

func NewRouter(dep Dependencies) http.Handler {
	r := mux.NewRouter()
	r.Use(requestIDMiddleware)

	registerAdminRoutes(r, dep.AdminStaticDir)
	registerNotifyRoutes(r, dep.NotifyStaticDir)

	r.HandleFunc("/health", healthHandler).Methods(http.MethodGet)
	r.HandleFunc("/login", loginPageHandler(dep.Flows, dep.Users)).Methods(http.MethodGet)
	r.HandleFunc("/login/select-user", loginSelectUserHandler(dep.Flows, dep.Users)).Methods(http.MethodPost)
	r.HandleFunc("/login/mfa", loginMFAHandler(dep.Flows, dep.Users)).Methods(http.MethodGet)
	r.HandleFunc("/login/mfa", loginMFASubmitHandler(dep.Flows, dep.Users)).Methods(http.MethodPost)
	r.HandleFunc("/login/complete", loginCompleteHandler(dep.Flows, dep.Users)).Methods(http.MethodGet)
	r.HandleFunc("/login/magic", loginMagicHandler(dep.Flows, dep.Users)).Methods(http.MethodGet)

	api := r.PathPrefix("/api/v1").Subrouter()
	api.Use(apiKeyMiddleware(dep.APIKey))

	if dep.RateLimit > 0 {
		rl := NewRateLimiter(dep.RateLimit, time.Minute)
		api.Use(rateLimitMiddleware(rl))
	}

	idempStore := newIdempotencyStore(5 * time.Minute)
	api.Use(idempotencyMiddleware(idempStore))

	// Meta endpoints — no auth needed even in protected mode.
	api.HandleFunc("/openapi.json", openAPISpecHandler).Methods(http.MethodGet)
	api.HandleFunc("/docs", openAPIDocsHandler).Methods(http.MethodGet)

	api.HandleFunc("/users", listUsersHandler(dep.Users)).Methods(http.MethodGet)
	api.HandleFunc("/users", createUserHandler(dep.Users, dep.Audit)).Methods(http.MethodPost)
	api.HandleFunc("/users/{id}", getUserHandler(dep.Users)).Methods(http.MethodGet)
	api.HandleFunc("/users/{id}", updateUserHandler(dep.Users, dep.Audit)).Methods(http.MethodPut)
	api.HandleFunc("/users/{id}", deleteUserHandler(dep.Users, dep.Audit)).Methods(http.MethodDelete)

	api.HandleFunc("/groups", listGroupsHandler(dep.Groups)).Methods(http.MethodGet)
	api.HandleFunc("/groups", createGroupHandler(dep.Groups)).Methods(http.MethodPost)
	api.HandleFunc("/groups/{id}", getGroupHandler(dep.Groups)).Methods(http.MethodGet)
	api.HandleFunc("/groups/{id}", updateGroupHandler(dep.Groups)).Methods(http.MethodPut)
	api.HandleFunc("/groups/{id}", deleteGroupHandler(dep.Groups)).Methods(http.MethodDelete)

	api.HandleFunc("/flows", listFlowsHandler(dep.Flows)).Methods(http.MethodGet)
	api.HandleFunc("/flows", createFlowHandler(dep.Flows)).Methods(http.MethodPost)
	api.HandleFunc("/flows/{id}", getFlowHandler(dep.Flows)).Methods(http.MethodGet)
	api.HandleFunc("/flows/{id}/select-user", selectUserFlowHandler(dep.Flows, dep.Users, dep.Audit)).Methods(http.MethodPost)
	api.HandleFunc("/flows/{id}/verify-mfa", verifyMFAFlowHandler(dep.Flows, dep.Users, dep.Audit)).Methods(http.MethodPost)
	api.HandleFunc("/flows/{id}/approve", approveFlowHandler(dep.Flows, dep.Users, dep.Audit)).Methods(http.MethodPost)
	api.HandleFunc("/flows/{id}/deny", denyFlowHandler(dep.Flows, dep.Audit)).Methods(http.MethodPost)
	api.HandleFunc("/flows/{id}/webauthn-response", webauthnResponseHandler(dep.Flows, dep.Users, dep.Audit)).Methods(http.MethodPost)

	api.HandleFunc("/sessions", listSessionsHandler(dep.Sessions)).Methods(http.MethodGet)
	api.HandleFunc("/notifications", listNotificationsHandler(dep.Flows, dep.Users, dep.BaseURL)).Methods(http.MethodGet)
	api.HandleFunc("/notifications/all", listAllNotificationsHandler(dep.Flows, dep.Users, dep.BaseURL)).Methods(http.MethodGet)

	api.HandleFunc("/tokens/mint", mintTokenHandler(dep.Users, dep.TokenMinter)).Methods(http.MethodPost)
	api.HandleFunc("/config", getConfigHandler(dep.ConfigPatcher)).Methods(http.MethodGet)
	api.HandleFunc("/config", patchConfigHandler(dep.ConfigPatcher)).Methods(http.MethodPatch)

	api.HandleFunc("/export", exportHandler(dep.Users, dep.Groups)).Methods(http.MethodGet)

	api.HandleFunc("/audit", auditListHandler(dep.Audit)).Methods(http.MethodGet)
	api.HandleFunc("/audit/export", auditExportHandler(dep.Audit)).Methods(http.MethodGet)

	// Mount SCIM 2.0 under /scim/v2 with its own credential.
	// SCIMKey takes precedence; falls back to APIKey so existing single-key
	// deployments continue to work without configuration changes.
	if dep.SCIMRouter != nil {
		scimKey := dep.SCIMKey
		if scimKey == "" {
			scimKey = dep.APIKey
		}
		scim := r.PathPrefix("/scim/v2").Subrouter()
		scim.Use(apiKeyMiddleware(scimKey))
		scim.PathPrefix("").Handler(dep.SCIMRouter)
	}

	return r
}

func openAPISpecHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(cachedSpec)
}

func openAPIDocsHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(openAPIDocsHTML))
}

func mintTokenHandler(users store.UserStore, minter TokenMinter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if minter == nil {
			writeAPIError(w, r, http.StatusNotImplemented, "NOT_IMPLEMENTED", "token minting is not configured", false)
			return
		}
		var req struct {
			UserID    string   `json:"user_id"`
			ClientID  string   `json:"client_id"`
			Scopes    []string `json:"scopes"`
			ExpiresIn int      `json:"expires_in"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAPIError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "invalid JSON body", false)
			return
		}
		if req.UserID == "" {
			writeAPIError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "user_id is required", false)
			return
		}
		user, err := users.GetByID(req.UserID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeAPIError(w, r, http.StatusNotFound, "RESOURCE_NOT_FOUND", "user not found", false)
				return
			}
			writeAPIError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error(), false)
			return
		}
		if req.ExpiresIn <= 0 {
			req.ExpiresIn = 3600
		}
		tokens, err := minter.MintForUser(user, req.ClientID, req.Scopes, req.ExpiresIn)
		if err != nil {
			writeAPIError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error(), false)
			return
		}
		writeJSON(w, http.StatusOK, tokens)
	}
}

func exportHandler(users store.UserStore, groups store.GroupStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rawFormat := strings.TrimSpace(r.URL.Query().Get("format"))
		if rawFormat == "" {
			writeAPIError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "format query parameter is required (scim, okta, azure, google)", false)
			return
		}
		f, err := export.ParseFormat(rawFormat)
		if err != nil {
			writeAPIError(w, r, http.StatusBadRequest, "INVALID_FORMAT", err.Error(), false)
			return
		}
		userList, err := users.List()
		if err != nil {
			writeAPIError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error(), false)
			return
		}
		groupList, err := groups.List()
		if err != nil {
			writeAPIError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error(), false)
			return
		}
		data, err := export.Users(userList, groupList, f)
		if err != nil {
			writeAPIError(w, r, http.StatusInternalServerError, "EXPORT_FAILED", err.Error(), false)
			return
		}
		w.Header().Set("Content-Type", export.ContentType(f))
		w.Header().Set("Content-Disposition", `attachment; filename="`+export.Filename(f)+`"`)
		_, _ = w.Write(data)
	}
}

func registerAdminRoutes(r *mux.Router, adminStaticDir string) {
	if adminStaticDir == "" {
		adminStaticDir = filepath.Join("server", "web", "static", "admin")
	}

	adminIndexPath := filepath.Join(adminStaticDir, "index.html")
	adminAssets := http.StripPrefix("/admin/", http.FileServer(http.Dir(adminStaticDir)))

	r.PathPrefix("/admin/assets/").Handler(adminAssets)
	r.Handle("/admin/vite.svg", adminAssets)
	r.HandleFunc("/admin", serveAdminIndex(adminIndexPath))
	r.PathPrefix("/admin/").HandlerFunc(serveAdminIndex(adminIndexPath))
}

func serveAdminIndex(indexPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := os.Stat(indexPath); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				writeError(w, http.StatusNotFound, "admin_spa_missing", "admin SPA index not found; run `make admin-build`")
				return
			}
			writeError(w, http.StatusInternalServerError, "admin_spa_unavailable", err.Error())
			return
		}

		http.ServeFile(w, r, indexPath)
	}
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"time":   time.Now().UTC(),
	})
}

func listUsersHandler(users store.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		result, err := users.List()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "list_users_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, result)
	}
}

func createUserHandler(users store.UserStore, as store.AuditStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := decodeUser(w, r.Body)
		if !ok {
			return
		}
		if user.ID == "" {
			writeError(w, http.StatusBadRequest, "validation_error", "id is required")
			return
		}
		if user.CreatedAt.IsZero() {
			user.CreatedAt = time.Now().UTC()
		}
		// Default to active — callers must explicitly set active=false to deactivate.
		if !user.Active {
			user.Active = true
		}
		created, err := users.Create(user)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "create_user_failed", err.Error())
			return
		}
		audit.Emit(as, audit.EventUserCreated, "system", created.ID, map[string]any{"email": created.Email})
		writeJSON(w, http.StatusCreated, created)
	}
}

func getUserHandler(users store.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		user, err := users.GetByID(id)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeError(w, http.StatusNotFound, "not_found", "user not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "get_user_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, user)
	}
}

func updateUserHandler(users store.UserStore, as store.AuditStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := decodeUser(w, r.Body)
		if !ok {
			return
		}
		id := mux.Vars(r)["id"]
		user.ID = id
		if user.CreatedAt.IsZero() {
			user.CreatedAt = time.Now().UTC()
		}
		updated, err := users.Update(user)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeError(w, http.StatusNotFound, "not_found", "user not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "update_user_failed", err.Error())
			return
		}
		audit.Emit(as, audit.EventUserUpdated, "system", updated.ID, map[string]any{"email": updated.Email})
		writeJSON(w, http.StatusOK, updated)
	}
}

func deleteUserHandler(users store.UserStore, as store.AuditStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		if err := users.Delete(id); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeError(w, http.StatusNotFound, "not_found", "user not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "delete_user_failed", err.Error())
			return
		}
		audit.Emit(as, audit.EventUserDeleted, "system", id, nil)
		w.WriteHeader(http.StatusNoContent)
	}
}

func listGroupsHandler(groups store.GroupStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		result, err := groups.List()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "list_groups_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, result)
	}
}

func createGroupHandler(groups store.GroupStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		group, ok := decodeGroup(w, r.Body)
		if !ok {
			return
		}
		if group.ID == "" {
			writeError(w, http.StatusBadRequest, "validation_error", "id is required")
			return
		}
		if group.CreatedAt.IsZero() {
			group.CreatedAt = time.Now().UTC()
		}
		created, err := groups.Create(group)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "create_group_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, created)
	}
}

func getGroupHandler(groups store.GroupStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		group, err := groups.GetByID(id)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeError(w, http.StatusNotFound, "not_found", "group not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "get_group_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, group)
	}
}

func updateGroupHandler(groups store.GroupStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		group, ok := decodeGroup(w, r.Body)
		if !ok {
			return
		}
		id := mux.Vars(r)["id"]
		group.ID = id
		if group.CreatedAt.IsZero() {
			group.CreatedAt = time.Now().UTC()
		}
		updated, err := groups.Update(group)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeError(w, http.StatusNotFound, "not_found", "group not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "update_group_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, updated)
	}
}

func deleteGroupHandler(groups store.GroupStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		if err := groups.Delete(id); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeError(w, http.StatusNotFound, "not_found", "group not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "delete_group_failed", err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func decodeUser(w http.ResponseWriter, body io.Reader) (domain.User, bool) {
	var user domain.User
	if err := json.NewDecoder(body).Decode(&user); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return domain.User{}, false
	}
	return user, true
}

func decodeGroup(w http.ResponseWriter, body io.Reader) (domain.Group, bool) {
	var group domain.Group
	if err := json.NewDecoder(body).Decode(&group); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return domain.Group{}, false
	}
	return group, true
}

func listSessionsHandler(sessions store.SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result, err := sessions.List()
		if err != nil {
			writeAPIError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list sessions", false)
			return
		}
		writeJSON(w, http.StatusOK, result)
	}
}

// listNotificationsHandler returns the notification payload for a single flow.
func listNotificationsHandler(flows store.FlowStore, users store.UserStore, baseURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flowID := strings.TrimSpace(r.URL.Query().Get("flow_id"))
		if flowID == "" {
			writeAPIError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "flow_id query parameter is required", false)
			return
		}
		flow, err := flows.GetByID(flowID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeAPIError(w, r, http.StatusNotFound, "FLOW_NOT_FOUND", "flow not found", false)
				return
			}
			writeAPIError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error(), false)
			return
		}
		user, _ := users.GetByID(flow.UserID)
		payload, updatedFlow, err := notify.GenerateFor(flow, user, baseURL)
		if err != nil {
			writeAPIError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error(), false)
			return
		}
		if updatedFlow.TOTPSecret != flow.TOTPSecret ||
			updatedFlow.SMSCode != flow.SMSCode ||
			updatedFlow.MagicLinkToken != flow.MagicLinkToken ||
			updatedFlow.WebAuthnChallenge != flow.WebAuthnChallenge {
			_, _ = flows.Update(updatedFlow)
		}
		writeJSON(w, http.StatusOK, payload)
	}
}

// listAllNotificationsHandler returns payloads for all flows currently in mfa_pending or webauthn_pending.
// Used by the /notify hub to show all pending approvals across users.
func listAllNotificationsHandler(flows store.FlowStore, users store.UserStore, baseURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		all, err := flows.List()
		if err != nil {
			writeAPIError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error(), false)
			return
		}
		var payloads []notify.Payload
		for _, flow := range all {
			if flow.State != "mfa_pending" && flow.State != "webauthn_pending" {
				continue
			}
			user, _ := users.GetByID(flow.UserID)
			payload, updatedFlow, err := notify.GenerateFor(flow, user, baseURL)
			if err != nil {
				continue
			}
			if updatedFlow.TOTPSecret != flow.TOTPSecret ||
				updatedFlow.SMSCode != flow.SMSCode ||
				updatedFlow.MagicLinkToken != flow.MagicLinkToken ||
				updatedFlow.WebAuthnChallenge != flow.WebAuthnChallenge {
				_, _ = flows.Update(updatedFlow)
			}
			payloads = append(payloads, payload)
		}
		if payloads == nil {
			payloads = []notify.Payload{}
		}
		writeJSON(w, http.StatusOK, payloads)
	}
}

// registerNotifyRoutes serves the /notify Vue SPA.
func registerNotifyRoutes(r *mux.Router, notifyStaticDir string) {
	if notifyStaticDir == "" {
		notifyStaticDir = filepath.Join("server", "web", "static", "notify")
	}
	indexPath := filepath.Join(notifyStaticDir, "index.html")
	assets := http.StripPrefix("/notify/", http.FileServer(http.Dir(notifyStaticDir)))

	r.PathPrefix("/notify/assets/").Handler(assets)
	r.HandleFunc("/notify", serveAdminIndex(indexPath))
	r.PathPrefix("/notify/").HandlerFunc(serveAdminIndex(indexPath))
}

// loginMagicHandler completes a flow via a magic link token.
func loginMagicHandler(flows store.FlowStore, users store.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimSpace(r.URL.Query().Get("token"))
		if token == "" {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "token is required")
			return
		}
		all, err := flows.List()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
			return
		}
		var matched *domain.Flow
		for i := range all {
			if all[i].MagicLinkToken == token && !all[i].MagicLinkUsed {
				matched = &all[i]
				break
			}
		}
		if matched == nil {
			writeError(w, http.StatusNotFound, "INVALID_REQUEST", "magic link not found or already used")
			return
		}
		if matched.State != "mfa_pending" {
			writeError(w, http.StatusConflict, "STATE_TRANSITION_INVALID", "flow is not awaiting MFA")
			return
		}
		matched.State = "mfa_approved"
		matched.MagicLinkUsed = true
		updated, err := flows.Update(*matched)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
			return
		}
		if user, err := users.GetByID(updated.UserID); err == nil {
			user.NextFlow = "normal"
			_, _ = users.Update(user)
		}
		http.Redirect(w, r, "/login/mfa?flow_id="+updated.ID, http.StatusFound)
	}
}

func getConfigHandler(cp ConfigPatcher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if cp == nil {
			writeAPIError(w, r, http.StatusNotImplemented, "NOT_IMPLEMENTED", "config management is not available", false)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"tokens": cp.GetTokenTTLs(),
		})
	}
}

// patchConfigRequest mirrors the subset of config that can be changed at runtime.
// Restart-required fields (http_addr, protocol_addr, oidc.issuer_url, persistence)
// are rejected with 400 restart_required: true if supplied.
type patchConfigRequest struct {
	Tokens            *TokenTTLs `json:"tokens"`
	// Restart-required sentinel fields — presence alone triggers the guard.
	HTTPAddr     *string `json:"http_addr"`
	ProtocolAddr *string `json:"protocol_addr"`
	IssuerURL    *string `json:"issuer_url"`
}

func patchConfigHandler(cp ConfigPatcher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if cp == nil {
			writeAPIError(w, r, http.StatusNotImplemented, "NOT_IMPLEMENTED", "config management is not available", false)
			return
		}
		var req patchConfigRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAPIError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "invalid JSON body", false)
			return
		}
		// Reject restart-required fields.
		if req.HTTPAddr != nil || req.ProtocolAddr != nil || req.IssuerURL != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": map[string]any{
					"code":             "RESTART_REQUIRED",
					"message":          "one or more fields require a server restart to take effect",
					"restart_required": true,
					"docs_url":         "/admin/docs/errors#restart_required",
				},
			})
			return
		}
		if req.Tokens != nil {
			if err := cp.SetTokenTTLs(*req.Tokens); err != nil {
				writeAPIError(w, r, http.StatusBadRequest, "INVALID_REQUEST", err.Error(), false)
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"tokens": cp.GetTokenTTLs(),
		})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeAPIError writes the standard spec error envelope.
// An optional details map[string]any may be passed as the last argument.
func writeAPIError(w http.ResponseWriter, r *http.Request, status int, code, message string, retryable bool, details ...map[string]any) {
	errObj := map[string]any{
		"code":      code,
		"message":   message,
		"retryable": retryable,
		"docs_url":  "/admin/docs/errors#" + strings.ToLower(code),
	}
	if len(details) > 0 && details[0] != nil {
		errObj["details"] = details[0]
	}
	body := map[string]any{
		"error":      errObj,
		"request_id": getRequestID(r),
	}
	writeJSON(w, status, body)
}

// writeError is kept for internal callers that don't have an *http.Request handy
// (login page handlers). It omits request_id.
func writeError(w http.ResponseWriter, status int, code string, message string, details ...map[string]any) {
	errObj := map[string]any{
		"code":      code,
		"message":   message,
		"retryable": false,
		"docs_url":  "/admin/docs/errors#" + strings.ToLower(code),
	}
	if len(details) > 0 && details[0] != nil {
		errObj["details"] = details[0]
	}
	writeJSON(w, status, map[string]any{
		"error": errObj,
	})
}
