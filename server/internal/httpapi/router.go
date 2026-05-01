package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"furnace/server/internal/audit"
	"furnace/server/internal/authevents"
	"furnace/server/internal/domain"
	"furnace/server/internal/export"
	"furnace/server/internal/notify"
	opaengine "furnace/server/internal/opa"
	"furnace/server/internal/store"
	"furnace/server/internal/store/tenanted"
)

// SCIMClient pushes user mutations to an external SCIM server.
// Implemented by scimclient.Client; nil = SCIM client mode disabled.
type SCIMClient interface {
	UserCreated(user domain.User)
	UserUpdated(user domain.User)
	UserDeleted(id string)
}

// SCIMEventLister returns the log of outbound SCIM client requests.
type SCIMEventLister interface {
	List() []domain.SCIMEvent
}

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
	AdminFS         fs.FS  // non-nil in prod builds: serve admin SPA from embedded FS
	APIKey          string        // single-tenant API key; required in single mode; ignored in multi-tenant mode (per-tenant keys live in TenantEntries)
	SCIMKey         string        // separate credential for /scim/v2; falls back to APIKey when empty
	BaseURL         string        // e.g. "http://localhost:8025" — used for magic link URLs
	RateLimit       int           // requests per minute per IP; 0 = disabled
	TrustedProxyCIDRs []*net.IPNet       // X-Forwarded-For honoured only when RemoteAddr is in one of these CIDRs; nil/empty = XFF ignored
	AuthEventSink   authevents.Sink    // nil = auth events discarded; set to authevents.Noop() or a WriterSink
	WebAuthnRPID    string             // FURNACE_WEBAUTHN_RP_ID / yaml webauthn.rp_id; required when WebAuthn endpoints are used — empty returns an error at the call site
	WebAuthnOrigin  string             // FURNACE_WEBAUTHN_ORIGIN / yaml webauthn.origin; required when WebAuthn endpoints are used — empty returns an error at the call site
	SCIMRouter      http.Handler  // mounted at /scim/v2; nil = disabled
	TokenMinter     TokenMinter   // nil = /tokens/mint endpoint returns 501
	ConfigPatcher   ConfigPatcher // nil = /config PATCH returns 501
	// TenantStores, if non-nil, overrides the static store fields on a per-request
	// basis using the tenant ID from the request context. Used only in multi mode.
	TenantStores   *tenanted.Dispatcher
	// TenantEntries maps API/SCIM keys to tenant IDs. Used by tenantAPIKeyMiddleware
	// in multi mode. Nil/empty = single mode.
	TenantEntries  []TenantEntry
	// SCIMClient, if non-nil, is called after successful user mutations to push
	// changes to an external SCIM target. nil = SCIM client mode disabled.
	SCIMClient     SCIMClient
	// SCIMEvents, if non-nil, backs GET /api/v1/scim/events.
	SCIMEvents     SCIMEventLister
	// ProtocolURL is the base URL of the protocol server (e.g. "http://localhost:18026").
	// Exposed via GET /api/v1/config so the admin SPA can build correct endpoint URLs.
	ProtocolURL    string
	// Readiness, if non-nil, is called by GET /ready to check store connectivity.
	// nil = always ready (memory store).
	Readiness      func() error
	// OPAEngine, if non-nil, enables the /api/v1/opa/* endpoints.
	// nil = OPA endpoints return 404.
	OPAEngine      *opaengine.Engine
	// OPAPolicies, if non-nil, enables the /api/v1/opa/policies/* Policy Admin endpoints.
	// nil = policy endpoints return 404.
	OPAPolicies    store.PolicyStore
	// APIKeyStore, if non-nil, enables the /api/v1/api-keys/* endpoints and allows
	// DB-issued keys to authenticate requests in addition to the static APIKey.
	APIKeyStore    store.APIKeyStore
}

// resolveStores returns the correct store set for the request context.
// In single mode (TenantStores == nil) it returns the static Dependencies fields.
// In multi mode it delegates to the Dispatcher.
func (d *Dependencies) resolveStores(ctx context.Context) (store.UserStore, store.GroupStore, store.FlowStore, store.SessionStore, store.AuditStore) {
	if d.TenantStores == nil {
		return d.Users, d.Groups, d.Flows, d.Sessions, d.Audit
	}
	s := d.TenantStores.ForContext(ctx)
	return s.Users, s.Groups, s.Flows, s.Sessions, s.Audit
}

func NewRouter(dep Dependencies) http.Handler {
	if dep.AuthEventSink == nil {
		dep.AuthEventSink = authevents.Noop()
	}

	r := mux.NewRouter()
	r.Use(requestIDMiddleware)
	r.Use(instrumentMiddleware)

	registerAdminRoutes(r, dep.AdminStaticDir, dep.AdminFS, dep.APIKey)

	r.HandleFunc("/", homeHandler(dep.APIKey)).Methods(http.MethodGet)

	r.HandleFunc("/health", healthHandler).Methods(http.MethodGet)
	r.HandleFunc("/ready", readyHandler(dep.Readiness)).Methods(http.MethodGet)
	r.Handle("/metrics", metricsHandler()).Methods(http.MethodGet)
	r.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		users, _, flows, _, _ := dep.resolveStores(r.Context())
		loginPageHandler(flows, users, dep.TrustedProxyCIDRs)(w, r)
	}).Methods(http.MethodGet)
	r.HandleFunc("/login/select-user", func(w http.ResponseWriter, r *http.Request) {
		users, _, flows, _, _ := dep.resolveStores(r.Context())
		loginSelectUserHandler(flows, users)(w, r)
	}).Methods(http.MethodPost)
	r.HandleFunc("/login/mfa", func(w http.ResponseWriter, r *http.Request) {
		users, _, flows, _, _ := dep.resolveStores(r.Context())
		loginMFAHandler(flows, users)(w, r)
	}).Methods(http.MethodGet)
	r.HandleFunc("/login/mfa", func(w http.ResponseWriter, r *http.Request) {
		users, _, flows, _, _ := dep.resolveStores(r.Context())
		loginMFASubmitHandler(flows, users, dep.AuthEventSink, dep.TrustedProxyCIDRs)(w, r)
	}).Methods(http.MethodPost)
	r.HandleFunc("/login/complete", func(w http.ResponseWriter, r *http.Request) {
		users, _, flows, _, _ := dep.resolveStores(r.Context())
		loginCompleteHandler(flows, users)(w, r)
	}).Methods(http.MethodGet)
	r.HandleFunc("/login/magic", func(w http.ResponseWriter, r *http.Request) {
		users, _, flows, _, _ := dep.resolveStores(r.Context())
		loginMagicHandler(flows, users)(w, r)
	}).Methods(http.MethodGet)

	// OpenAPI spec and Swagger UI are public — no auth required.
	r.HandleFunc("/api/v1/openapi.json", openAPISpecHandler).Methods(http.MethodGet)
	r.HandleFunc("/api/v1/docs", openAPIDocsHandler).Methods(http.MethodGet)

	// Docs — public, no auth required.
	r.HandleFunc("/doc", docIndexHandler()).Methods(http.MethodGet)
	r.HandleFunc("/doc/{slug}", docHandler()).Methods(http.MethodGet)

	api := r.PathPrefix("/api/v1").Subrouter()
	if dep.TenantStores != nil && len(dep.TenantEntries) > 0 {
		api.Use(tenantAPIKeyMiddleware(dep.TenantEntries, dep.AuthEventSink, dep.TrustedProxyCIDRs))
	} else {
		api.Use(apiKeyMiddleware(dep.APIKey, dep.APIKeyStore, dep.AuthEventSink, dep.TrustedProxyCIDRs))
	}

	if dep.RateLimit > 0 {
		rl := NewRateLimiter(dep.RateLimit, time.Minute)
		api.Use(rateLimitMiddleware(rl, dep.TrustedProxyCIDRs, dep.AuthEventSink))
	}

	idempStore := newIdempotencyStore(5 * time.Minute)
	api.Use(idempotencyMiddleware(idempStore))

	api.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		users, _, _, _, _ := dep.resolveStores(r.Context())
		listUsersHandler(users)(w, r)
	}).Methods(http.MethodGet)
	api.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		users, _, _, _, as := dep.resolveStores(r.Context())
		createUserHandler(users, as, dep.SCIMClient)(w, r)
	}).Methods(http.MethodPost)
	api.HandleFunc("/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		users, _, _, _, _ := dep.resolveStores(r.Context())
		getUserHandler(users)(w, r)
	}).Methods(http.MethodGet)
	api.HandleFunc("/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		users, _, _, _, as := dep.resolveStores(r.Context())
		updateUserHandler(users, as, dep.SCIMClient)(w, r)
	}).Methods(http.MethodPut)
	api.HandleFunc("/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		users, _, _, _, as := dep.resolveStores(r.Context())
		deleteUserHandler(users, as, dep.SCIMClient)(w, r)
	}).Methods(http.MethodDelete)

	api.HandleFunc("/groups", func(w http.ResponseWriter, r *http.Request) {
		_, groups, _, _, _ := dep.resolveStores(r.Context())
		listGroupsHandler(groups)(w, r)
	}).Methods(http.MethodGet)
	api.HandleFunc("/groups", func(w http.ResponseWriter, r *http.Request) {
		_, groups, _, _, _ := dep.resolveStores(r.Context())
		createGroupHandler(groups)(w, r)
	}).Methods(http.MethodPost)
	api.HandleFunc("/groups/{id}", func(w http.ResponseWriter, r *http.Request) {
		_, groups, _, _, _ := dep.resolveStores(r.Context())
		getGroupHandler(groups)(w, r)
	}).Methods(http.MethodGet)
	api.HandleFunc("/groups/{id}", func(w http.ResponseWriter, r *http.Request) {
		_, groups, _, _, _ := dep.resolveStores(r.Context())
		updateGroupHandler(groups)(w, r)
	}).Methods(http.MethodPut)
	api.HandleFunc("/groups/{id}", func(w http.ResponseWriter, r *http.Request) {
		_, groups, _, _, _ := dep.resolveStores(r.Context())
		deleteGroupHandler(groups)(w, r)
	}).Methods(http.MethodDelete)

	api.HandleFunc("/flows", func(w http.ResponseWriter, r *http.Request) {
		_, _, flows, _, _ := dep.resolveStores(r.Context())
		listFlowsHandler(flows)(w, r)
	}).Methods(http.MethodGet)
	api.HandleFunc("/flows", func(w http.ResponseWriter, r *http.Request) {
		_, _, flows, _, _ := dep.resolveStores(r.Context())
		createFlowHandler(flows)(w, r)
	}).Methods(http.MethodPost)
	api.HandleFunc("/flows/{id}", func(w http.ResponseWriter, r *http.Request) {
		_, _, flows, _, _ := dep.resolveStores(r.Context())
		getFlowHandler(flows)(w, r)
	}).Methods(http.MethodGet)
	api.HandleFunc("/flows/{id}/select-user", func(w http.ResponseWriter, r *http.Request) {
		users, _, flows, _, as := dep.resolveStores(r.Context())
		selectUserFlowHandler(flows, users, as)(w, r)
	}).Methods(http.MethodPost)
	api.HandleFunc("/flows/{id}/verify-mfa", func(w http.ResponseWriter, r *http.Request) {
		users, _, flows, _, as := dep.resolveStores(r.Context())
		verifyMFAFlowHandler(flows, users, as, dep.AuthEventSink, dep.TrustedProxyCIDRs)(w, r)
	}).Methods(http.MethodPost)
	api.HandleFunc("/flows/{id}/approve", func(w http.ResponseWriter, r *http.Request) {
		users, _, flows, _, as := dep.resolveStores(r.Context())
		approveFlowHandler(flows, users, as)(w, r)
	}).Methods(http.MethodPost)
	api.HandleFunc("/flows/{id}/deny", func(w http.ResponseWriter, r *http.Request) {
		_, _, flows, _, as := dep.resolveStores(r.Context())
		denyFlowHandler(flows, as, dep.AuthEventSink, dep.TrustedProxyCIDRs)(w, r)
	}).Methods(http.MethodPost)
	wa := webAuthnSettings{RPID: dep.WebAuthnRPID, Origin: dep.WebAuthnOrigin}
	api.HandleFunc("/flows/{id}/webauthn-begin-register", func(w http.ResponseWriter, r *http.Request) {
		users, _, flows, _, _ := dep.resolveStores(r.Context())
		webauthnBeginRegisterHandler(flows, users, wa)(w, r)
	}).Methods(http.MethodGet)
	api.HandleFunc("/flows/{id}/webauthn-finish-register", func(w http.ResponseWriter, r *http.Request) {
		users, _, flows, _, _ := dep.resolveStores(r.Context())
		webauthnFinishRegisterHandler(flows, users, wa)(w, r)
	}).Methods(http.MethodPost)
	api.HandleFunc("/flows/{id}/webauthn-begin", func(w http.ResponseWriter, r *http.Request) {
		users, _, flows, _, _ := dep.resolveStores(r.Context())
		webauthnBeginHandler(flows, users, wa)(w, r)
	}).Methods(http.MethodGet)
	api.HandleFunc("/flows/{id}/webauthn-response", func(w http.ResponseWriter, r *http.Request) {
		users, _, flows, _, as := dep.resolveStores(r.Context())
		webauthnResponseHandler(flows, users, as, wa, dep.AuthEventSink, dep.TrustedProxyCIDRs)(w, r)
	}).Methods(http.MethodPost)

	api.HandleFunc("/sessions", func(w http.ResponseWriter, r *http.Request) {
		_, _, _, sessions, _ := dep.resolveStores(r.Context())
		listSessionsHandler(sessions)(w, r)
	}).Methods(http.MethodGet)
	api.HandleFunc("/notifications", func(w http.ResponseWriter, r *http.Request) {
		users, _, flows, _, _ := dep.resolveStores(r.Context())
		listNotificationsHandler(flows, users, dep.BaseURL)(w, r)
	}).Methods(http.MethodGet)
	api.HandleFunc("/notifications/all", func(w http.ResponseWriter, r *http.Request) {
		users, _, flows, _, _ := dep.resolveStores(r.Context())
		listAllNotificationsHandler(flows, users, dep.BaseURL)(w, r)
	}).Methods(http.MethodGet)

	api.HandleFunc("/tokens/mint", func(w http.ResponseWriter, r *http.Request) {
		users, _, _, _, _ := dep.resolveStores(r.Context())
		mintTokenHandler(users, dep.TokenMinter)(w, r)
	}).Methods(http.MethodPost)
	api.HandleFunc("/config", getConfigHandler(dep.ConfigPatcher, dep.ProtocolURL)).Methods(http.MethodGet)
	api.HandleFunc("/config", patchConfigHandler(dep.ConfigPatcher)).Methods(http.MethodPatch)

	api.HandleFunc("/export", func(w http.ResponseWriter, r *http.Request) {
		users, groups, _, _, _ := dep.resolveStores(r.Context())
		exportHandler(users, groups)(w, r)
	}).Methods(http.MethodGet)

	api.HandleFunc("/audit", func(w http.ResponseWriter, r *http.Request) {
		_, _, _, _, as := dep.resolveStores(r.Context())
		auditListHandler(as)(w, r)
	}).Methods(http.MethodGet)
	api.HandleFunc("/audit/export", func(w http.ResponseWriter, r *http.Request) {
		_, _, _, _, as := dep.resolveStores(r.Context())
		auditExportHandler(as)(w, r)
	}).Methods(http.MethodGet)
	api.HandleFunc("/audit/verify", func(w http.ResponseWriter, r *http.Request) {
		_, _, _, _, as := dep.resolveStores(r.Context())
		auditVerifyHandler(as)(w, r)
	}).Methods(http.MethodGet)

	registerDebugRoutes(api, &dep)

	api.HandleFunc("/scim/events", scimEventsHandler(dep.SCIMEvents)).Methods(http.MethodGet)

	if dep.APIKeyStore != nil {
		api.HandleFunc("/api-keys", listAPIKeysHandler(dep.APIKeyStore)).Methods(http.MethodGet)
		api.HandleFunc("/api-keys", createAPIKeyHandler(dep.APIKeyStore)).Methods(http.MethodPost)
		api.HandleFunc("/api-keys/{id}", getAPIKeyHandler(dep.APIKeyStore)).Methods(http.MethodGet)
		api.HandleFunc("/api-keys/{id}", revokeAPIKeyHandler(dep.APIKeyStore)).Methods(http.MethodDelete)
	}

	if dep.OPAEngine != nil {
		opaengine.NewRouter(opaengine.RouterDeps{
			Engine:   dep.OPAEngine,
			Users:    dep.Users,
			Policies: dep.OPAPolicies,
		}, r, api)
	}

	// Mount SCIM 2.0 under /scim/v2 with its own credential.
	if dep.SCIMRouter != nil {
		scim := r.PathPrefix("/scim/v2").Subrouter()
		if dep.TenantStores != nil && len(dep.TenantEntries) > 0 {
			// Multi mode: resolve tenant from SCIM/API key.
			scim.Use(tenantAPIKeyMiddleware(dep.TenantEntries, dep.AuthEventSink, dep.TrustedProxyCIDRs))
		} else {
			// Single mode: SCIMKey takes precedence; falls back to APIKey.
			scimKey := dep.SCIMKey
			if scimKey == "" {
				scimKey = dep.APIKey
			}
			scim.Use(apiKeyMiddleware(scimKey, dep.APIKeyStore, dep.AuthEventSink, dep.TrustedProxyCIDRs))
		}
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

func registerAdminRoutes(r *mux.Router, adminStaticDir string, adminFS fs.FS, apiKey string) {
	if adminFS != nil {
		// Prod: serve from embedded filesystem.
		fileServer := http.FileServer(http.FS(adminFS))
		r.PathPrefix("/admin/assets/").Handler(http.StripPrefix("/admin/", fileServer))
		r.Handle("/admin/vite.svg", http.StripPrefix("/admin/", fileServer))
		r.HandleFunc("/admin", serveAdminIndexFS(adminFS, apiKey))
		r.PathPrefix("/admin/").HandlerFunc(serveAdminIndexFS(adminFS, apiKey))
		return
	}

	// Dev: serve from disk.
	if adminStaticDir == "" {
		adminStaticDir = filepath.Join("server", "web", "static", "admin")
	}
	adminIndexPath := filepath.Join(adminStaticDir, "index.html")
	adminAssets := http.StripPrefix("/admin/", http.FileServer(http.Dir(adminStaticDir)))

	r.PathPrefix("/admin/assets/").Handler(adminAssets)
	r.Handle("/admin/vite.svg", adminAssets)
	r.HandleFunc("/admin", serveAdminIndex(adminIndexPath, apiKey))
	r.PathPrefix("/admin/").HandlerFunc(serveAdminIndex(adminIndexPath, apiKey))
}

// injectAdminConfig inserts window.__FURNACE__ config before </head> so the SPA
// can read the API key at runtime without baking it into the Vite build.
func injectAdminConfig(html []byte, apiKey string) []byte {
	cfg, _ := json.Marshal(map[string]string{"apiKey": apiKey})
	inject := []byte(`<script>window.__FURNACE__=` + string(cfg) + `</script>`)
	return bytes.Replace(html, []byte(`</head>`), append(inject, []byte(`</head>`)...), 1)
}

func serveAdminIndexFS(adminFS fs.FS, apiKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f, err := adminFS.Open("index.html")
		if err != nil {
			writeError(w, http.StatusInternalServerError, "admin_spa_unavailable", err.Error())
			return
		}
		defer f.Close()
		content, err := io.ReadAll(f)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "admin_spa_unavailable", err.Error())
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(injectAdminConfig(content, apiKey))
	}
}

func serveAdminIndex(indexPath, apiKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		content, err := os.ReadFile(indexPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				writeError(w, http.StatusNotFound, "admin_spa_missing", "admin SPA index not found; run `make admin-build`")
				return
			}
			writeError(w, http.StatusInternalServerError, "admin_spa_unavailable", err.Error())
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(injectAdminConfig(content, apiKey))
	}
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"time":   time.Now().UTC(),
	})
}

func readyHandler(readiness func() error) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if readiness != nil {
			if err := readiness(); err != nil {
				writeJSON(w, http.StatusServiceUnavailable, map[string]any{
					"status": "not_ready",
					"error":  err.Error(),
				})
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "ready"})
	}
}

func listUsersHandler(users store.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		result, err := users.List()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "list_users_failed", err.Error())
			return
		}
		if result == nil {
			result = []domain.User{}
		}
		writeJSON(w, http.StatusOK, result)
	}
}

func createUserHandler(users store.UserStore, as store.AuditStore, sc SCIMClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := decodeUser(w, r.Body)
		if !ok {
			return
		}
		if user.ID == "" {
			user.ID = fmt.Sprintf("usr_%d", time.Now().UnixNano())
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
		if sc != nil {
			sc.UserCreated(created)
		}
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

func updateUserHandler(users store.UserStore, as store.AuditStore, sc SCIMClient) http.HandlerFunc {
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
		if sc != nil {
			sc.UserUpdated(updated)
		}
		writeJSON(w, http.StatusOK, updated)
	}
}

func deleteUserHandler(users store.UserStore, as store.AuditStore, sc SCIMClient) http.HandlerFunc {
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
		if sc != nil {
			sc.UserDeleted(id)
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func scimEventsHandler(events SCIMEventLister) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if events == nil {
			writeAPIError(w, r, http.StatusNotImplemented, "NOT_IMPLEMENTED", "SCIM client mode is not enabled", false)
			return
		}
		list := events.List()
		if list == nil {
			list = []domain.SCIMEvent{}
		}
		writeJSON(w, http.StatusOK, list)
	}
}

func listGroupsHandler(groups store.GroupStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		result, err := groups.List()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "list_groups_failed", err.Error())
			return
		}
		if result == nil {
			result = []domain.Group{}
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
			group.ID = fmt.Sprintf("grp_%d", time.Now().UnixNano())
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
		if result == nil {
			result = []domain.Session{}
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

func getConfigHandler(cp ConfigPatcher, protocolURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if cp == nil {
			writeAPIError(w, r, http.StatusNotImplemented, "NOT_IMPLEMENTED", "config management is not available", false)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"tokens":       cp.GetTokenTTLs(),
			"protocol_url": protocolURL,
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
