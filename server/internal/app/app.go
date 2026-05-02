package app

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"furnace/server/internal/authevents"
	"furnace/server/internal/config"
	"furnace/server/internal/domain"
	"furnace/server/internal/httpapi"
	oidcengine "furnace/server/internal/oidc"
	opaengine "furnace/server/internal/opa"
	"furnace/server/internal/personality"
	samlengine "furnace/server/internal/saml"
	"furnace/server/internal/scim"
	"furnace/server/internal/scimclient"
	"furnace/server/internal/store"
	"furnace/server/internal/store/memory"
	sqliteStore "furnace/server/internal/store/sqlite"
	"furnace/server/internal/store/tenanted"
	"furnace/server/internal/tenant"
	wsfedengine "furnace/server/internal/wsfed"
	"furnace/server/web"
)

// auditCap is the maximum number of audit events held in memory.
const auditCap = 10_000

type App struct {
	cfg    config.Config
	logger *slog.Logger

	users    store.UserStore
	groups   store.GroupStore
	flows    store.FlowStore
	sessions store.SessionStore

	km              *oidcengine.KeyManager
	rotationInterval time.Duration

	httpServer     *http.Server
	protocolServer *http.Server
	closers        []func() error
	cleanupDone    chan struct{}
}

func New(cfg config.Config, logger *slog.Logger) (*App, error) {
	var users store.UserStore
	var groups store.GroupStore
	closers := make([]func() error, 0)

	var flows store.FlowStore
	var sessions store.SessionStore
	var policies store.PolicyStore
	var apiKeys store.APIKeyStore
	var readiness func() error
	var auditStore store.AuditStore = memory.NewAuditStore(auditCap)

	var sq *sqliteStore.Store
	if cfg.Persistence.Enabled {
		var err error
		sq, err = sqliteStore.New(cfg.Persistence.SQLitePath)
		if err != nil {
			return nil, fmt.Errorf("initialize sqlite persistence: %w", err)
		}
		users = sq.Users()
		groups = sq.Groups()
		flows = sq.Flows()
		sessions = sq.Sessions()
		policies = sq.Policies()
		apiKeys = sq.APIKeys()
		auditStore = sq.Audit()
		closers = append(closers, sq.Close)
		readiness = sq.Ping
	} else {
		users = memory.NewUserStore()
		groups = memory.NewGroupStore()
		flows = memory.NewFlowStore()
		sessions = memory.NewSessionStore()
	}
	scimEventStore := memory.NewSCIMEventStore(auditCap)

	if err := seedUsers(users, cfg.SeedUsers); err != nil {
		return nil, fmt.Errorf("seed users: %w", err)
	}

	if len(cfg.SessionHashKey) == 0 {
		if sq != nil {
			var err error
			cfg.SessionHashKey, err = sq.LoadOrCreateSessionHashKey()
			if err != nil {
				return nil, fmt.Errorf("session hash key: %w", err)
			}
		} else {
			cfg.SessionHashKey = make([]byte, 32)
			if _, err := rand.Read(cfg.SessionHashKey); err != nil {
				return nil, fmt.Errorf("generate session hash key: %w", err)
			}
		}
	}

	if cfg.APIKey == "" && cfg.Tenancy != "multi" {
		b := make([]byte, 20)
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("generate api key: %w", err)
		}
		cfg.APIKey = "furn_" + hex.EncodeToString(b)
	} else if len(cfg.APIKey) < 16 && cfg.Tenancy != "multi" {
		logger.Warn("api key is shorter than 16 characters; use a stronger key in production",
			"length", len(cfg.APIKey))
	}

	httpBaseURL := "http://localhost" + cfg.HTTPAddr
	km, err := oidcengine.NewKeyManagerWithOverlap(cfg.OIDC.KeyRotationOverlap)
	if err != nil {
		return nil, fmt.Errorf("initialize oidc key manager: %w", err)
	}
	tokenCfg := oidcengine.TokenConfig{
		AccessTokenTTL:  cfg.OIDC.AccessTokenTTL,
		IDTokenTTL:      cfg.OIDC.IDTokenTTL,
		RefreshTokenTTL: cfg.OIDC.RefreshTokenTTL,
		IncludeJTI:      cfg.Tokens.Format.IncludeJTI,
		AudAsArray:      cfg.Tokens.Format.AudAsArray,
		IncludeScope:    cfg.Tokens.Format.IncludeScope,
		HasuraClaims: oidcengine.HasuraClaimsConfig{
			Enabled:      cfg.Tokens.HasuraClaims.Enabled,
			Namespace:    cfg.Tokens.HasuraClaims.Namespace,
			DefaultRole:  cfg.Tokens.HasuraClaims.DefaultRole,
			AllowedRoles: cfg.Tokens.HasuraClaims.AllowedRoles,
		},
	}
	issuer := oidcengine.NewIssuer(km, tokenCfg, cfg.OIDC.IssuerURL)
	if cfg.Provider != "" {
		if p, ok := personality.Get(cfg.Provider); ok {
			issuer.SetPersonality(p)
		}
	}

	cp := &issuerConfigPatcher{issuer: issuer}

	// Build per-tenant store sets and the dispatcher used by handlers.
	// In single mode there is exactly one tenant ("default") wrapping the raw stores.
	// In multi mode there is one set per configured tenant plus the default.
	dispatcher, tenantEntries := buildTenantStores(cfg, users, groups, flows, sessions, auditStore)

	scimRouter := scim.NewRouter(scim.RouterDeps{
		Users:  dispatcher.ForContext(tenant.WithTenant(context.Background(), tenant.DefaultTenantID)).Users,
		Groups: dispatcher.ForContext(tenant.WithTenant(context.Background(), tenant.DefaultTenantID)).Groups,
	})

	var scimCl httpapi.SCIMClient
	if cfg.SCIMClientMode {
		scimCl = scimclient.New(cfg.SCIMTargetURL, scimEventStore)
	}

	protocolBase := "http://localhost" + cfg.ProtocolAddr

	trustedProxyCIDRs := make([]*net.IPNet, 0, len(cfg.TrustedProxyCIDRs))
	for _, raw := range cfg.TrustedProxyCIDRs {
		_, n, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("FURNACE_TRUSTED_PROXY_CIDRS: invalid CIDR %q: %w", raw, err)
		}
		trustedProxyCIDRs = append(trustedProxyCIDRs, n)
	}

	authSink, authSinkCloser, err := authevents.NewSink(cfg.AuthEventLog)
	if err != nil {
		return nil, fmt.Errorf("auth event sink: %w", err)
	}
	closers = append(closers, authSinkCloser.Close)

	opaEngine, err := opaengine.NewEngine(cfg.OPA)
	if err != nil {
		return nil, fmt.Errorf("initialize opa engine: %w", err)
	}

	router := httpapi.NewRouter(httpapi.Dependencies{
		Users:             users,
		Groups:            groups,
		Flows:             flows,
		Sessions:          sessions,
		Audit:             auditStore,
		APIKey:            cfg.APIKey,
		SessionHashKey:    base64.StdEncoding.EncodeToString(cfg.SessionHashKey),
		SCIMKey:           cfg.SCIMKey,
		BaseURL:           httpBaseURL,
		ProtocolURL:       protocolBase,
		RateLimit:         cfg.RateLimit,
		TrustedProxyCIDRs: trustedProxyCIDRs,
		AuthEventSink:     authSink,
		WebAuthnRPID:      cfg.WebAuthn.RPID,
		WebAuthnOrigin:    cfg.WebAuthn.Origin,
		SCIMRouter:        scimRouter,
		TokenMinter:       &issuerMinter{issuer: issuer},
		ConfigPatcher:     cp,
		TenantStores:      dispatcher,
		TenantEntries:     tenantEntries,
		SCIMClient:        scimCl,
		SCIMEvents:        scimEventStore,
		AdminFS:           web.AdminFS,
		Readiness:         readiness,
		OPAEngine:         opaEngine,
		OPAPolicies:       policies,
		APIKeyStore:       apiKeys,
	})

	httpServer := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
	}

	loginURL := "http://localhost" + cfg.HTTPAddr + "/login"
	headerMappings := make([]oidcengine.HeaderMapping, len(cfg.HeaderMappings))
	for idx, m := range cfg.HeaderMappings {
		headerMappings[idx] = oidcengine.HeaderMapping{Name: m.Name, Claim: m.Claim, Join: m.Join}
	}

	oidcRouter := oidcengine.NewRouter(oidcengine.RouterDeps{
		Flows:             flows,
		Users:             users,
		Sessions:          sessions,
		KeyMgr:            km,
		Issuer:            issuer,
		IssuerURL:         cfg.OIDC.IssuerURL,
		LoginURL:          loginURL,
		HeaderPropagation: cfg.HeaderPropagation,
		HeaderMappings:    headerMappings,
		SessionHashKey:    cfg.SessionHashKey,
	})

	samlCertMgr, err := samlengine.NewCertManagerFromPath(cfg.SAML.CertDir)
	if err != nil {
		return nil, fmt.Errorf("initialize saml cert manager: %w", err)
	}
	samlEntityID := cfg.SAML.EntityID
	samlRouter := samlengine.NewRouter(samlengine.RouterDeps{
		Flows:      flows,
		Users:      users,
		Sessions:   sessions,
		CertMgr:    samlCertMgr,
		EntityID:   samlEntityID,
		SSOURL:     samlEntityID + "/saml/sso",
		SLOURL:     samlEntityID + "/saml/slo",
		LoginURL:   loginURL,
		SessionTTL: 1 * time.Hour,
	})

	wsfedRouter := wsfedengine.NewRouter(wsfedengine.RouterDeps{
		Users:      users,
		Sessions:   sessions,
		CertMgr:    samlCertMgr,
		EntityID:   samlEntityID,
		IssuerURL:  protocolBase + "/wsfed",
		LoginURL:   loginURL,
		SessionTTL: 1 * time.Hour,
	})

	// Combine OIDC, SAML, and WS-Fed on the protocol server using path-based dispatch.
	protocolMux := http.NewServeMux()
	protocolMux.Handle("/saml/", samlRouter)
	protocolMux.Handle("/wsfed", wsfedRouter)
	protocolMux.Handle("/federationmetadata/", wsfedRouter)
	protocolMux.Handle("/", oidcRouter)

	protocolServer := &http.Server{
		Addr:              cfg.ProtocolAddr,
		Handler:           corsMiddleware(cfg.CORSOrigins)(protocolMux),
		ReadHeaderTimeout: 5 * time.Second,
	}

	return &App{
		cfg:              cfg,
		logger:           logger,
		users:            users,
		groups:           groups,
		flows:            flows,
		sessions:         sessions,
		km:               km,
		rotationInterval: cfg.OIDC.KeyRotationInterval,
		httpServer:       httpServer,
		protocolServer:   protocolServer,
		closers:          closers,
		cleanupDone:      make(chan struct{}),
	}, nil
}

func (a *App) Start(ctx context.Context) error {
	a.km.StartRotation(ctx, a.rotationInterval, func(err error) {
		if err != nil {
			a.logger.Warn("oidc signing key rotation failed", "error", err)
		} else {
			a.logger.Info("oidc signing key rotated")
		}
	})

	a.logger.Info("furnace starting",
		"http_addr", a.cfg.HTTPAddr,
		"protocol_addr", a.cfg.ProtocolAddr,
		"log_level", a.cfg.LogLevel,
		"persistence", a.cfg.Persistence.Enabled,
		"rate_limit", a.cfg.RateLimit,
		"seed_users", len(a.cfg.SeedUsers),
		"oidc_issuer", a.cfg.OIDC.IssuerURL,
		"access_token_ttl", a.cfg.OIDC.AccessTokenTTL,
		"id_token_ttl", a.cfg.OIDC.IDTokenTTL,
		"refresh_token_ttl", a.cfg.OIDC.RefreshTokenTTL,
		"header_propagation", a.cfg.HeaderPropagation,
	)
	a.startCleanupScheduler(ctx)

	errCh := make(chan error, 2)

	go func() {
		a.logger.Info("http server listening", "addr", a.cfg.HTTPAddr)
		if err := a.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("http server: %w", err)
		}
	}()

	go func() {
		a.logger.Info("oidc protocol server listening", "addr", a.cfg.ProtocolAddr)
		if err := a.protocolServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("protocol server: %w", err)
		}
	}()

	select {
	case <-ctx.Done():
		a.logger.Info("shutdown signal received")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := a.httpServer.Shutdown(shutdownCtx); err != nil {
			a.logger.Warn("shutdown http server", "error", err)
		}
		if err := a.protocolServer.Shutdown(shutdownCtx); err != nil {
			a.logger.Warn("shutdown protocol server", "error", err)
		}
		<-a.cleanupDone
		for _, closeFn := range a.closers {
			if err := closeFn(); err != nil {
				a.logger.Warn("resource close failed", "error", err)
			}
		}
		return nil
	case err := <-errCh:
		return err
	}
}

func (a *App) startCleanupScheduler(ctx context.Context) {
	ticker := time.NewTicker(a.cfg.Cleanup.Interval)
	go func() {
		defer ticker.Stop()
		defer close(a.cleanupDone)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := time.Now().UTC()
				flowRemoved, flowErr := a.flows.DeleteExpired(now)
				sessionRemoved, sessionErr := a.sessions.DeleteExpired(now)
				if flowErr != nil {
					a.logger.Warn("flow cleanup failed", "error", flowErr)
				}
				if sessionErr != nil {
					a.logger.Warn("session cleanup failed", "error", sessionErr)
				}
				if flowRemoved > 0 || sessionRemoved > 0 {
					a.logger.Info("cleanup completed", "flows_removed", flowRemoved, "sessions_removed", sessionRemoved)
				}
			}
		}
	}()
}

// buildTenantStores creates the tenanted store dispatcher and the tenant entry
// list used by the API key middleware.
//
// In single mode: one "default" tenant wrapping the raw stores.
// In multi mode: one set per configured tenant plus "default" as fallback.
func buildTenantStores(
	cfg config.Config,
	users store.UserStore,
	groups store.GroupStore,
	flows store.FlowStore,
	sessions store.SessionStore,
	audit store.AuditStore,
) (*tenanted.Dispatcher, []httpapi.TenantEntry) {
	sets := make(map[string]*tenanted.StoreSet)
	var entries []httpapi.TenantEntry

	addTenant := func(tid string) {
		sets[tid] = &tenanted.StoreSet{
			Users:    tenanted.NewUserStore(users, tid),
			Groups:   tenanted.NewGroupStore(groups, tid),
			Flows:    tenanted.NewFlowStore(flows, tid),
			Sessions: tenanted.NewSessionStore(sessions, tid),
			Audit:    tenanted.NewAuditStore(audit, tid),
		}
	}

	// Always create the default tenant.
	addTenant(tenant.DefaultTenantID)

	if cfg.Tenancy == config.TenancyMulti {
		for _, t := range cfg.Tenants {
			addTenant(t.ID)
			scimKey := t.SCIMKey
			if scimKey == "" {
				scimKey = t.APIKey
			}
			entries = append(entries, httpapi.TenantEntry{
				TenantID: t.ID,
				APIKey:   t.APIKey,
				SCIMKey:  scimKey,
			})
		}
	}

	return tenanted.NewDispatcher(sets), entries
}

// seedUsers upserts each seed user into the store. Create is tried first;
// if the record already exists it is updated so re-starts are idempotent.
func seedUsers(users store.UserStore, seeds []config.SeedUser) error {
	for _, s := range seeds {
		active := true
		if s.Active != nil {
			active = *s.Active
		}
		u := domain.User{
			ID:          s.ID,
			Email:       s.Email,
			DisplayName: s.DisplayName,
			Groups:      s.Groups,
			MFAMethod:   s.MFAMethod,
			NextFlow:    s.NextFlow,
			Active:      active,
			Claims:      s.Claims,
			PhoneNumber: s.PhoneNumber,
			CreatedAt:   time.Now().UTC(),
		}
		if _, err := users.Create(u); err != nil {
			// Already exists — update instead so re-starts stay idempotent.
			if _, err2 := users.Update(u); err2 != nil {
				return fmt.Errorf("upsert seed user %q: %w", s.ID, err2)
			}
		}
	}
	return nil
}

// corsMiddleware returns a middleware that applies CORS headers to protocol server responses.
// When origins is empty, Access-Control-Allow-Origin is set to "*".
// When origins is non-empty, only requests from a listed origin receive the matching header.
// Set FURNACE_CORS_ORIGINS (comma-separated) to restrict allowed origins in production.
func corsMiddleware(origins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(origins) == 0 {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			} else {
				requestOrigin := r.Header.Get("Origin")
				for _, o := range origins {
					if o == requestOrigin {
						w.Header().Set("Access-Control-Allow-Origin", requestOrigin)
						w.Header().Add("Vary", "Origin")
						break
					}
				}
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// issuerConfigPatcher adapts oidcengine.Issuer to the httpapi.ConfigPatcher interface.
type issuerConfigPatcher struct {
	issuer *oidcengine.Issuer
}

func (p *issuerConfigPatcher) GetTokenTTLs() httpapi.TokenTTLs {
	cfg := p.issuer.GetTokenConfig()
	atTTL := int(cfg.AccessTokenTTL.Seconds())
	idTTL := int(cfg.IDTokenTTL.Seconds())
	rtTTL := int(cfg.RefreshTokenTTL.Seconds())
	return httpapi.TokenTTLs{
		AccessTokenTTL:  &atTTL,
		IDTokenTTL:      &idTTL,
		RefreshTokenTTL: &rtTTL,
	}
}

func (p *issuerConfigPatcher) SetTokenTTLs(ttls httpapi.TokenTTLs) error {
	cfg := p.issuer.GetTokenConfig()
	if ttls.AccessTokenTTL != nil {
		if *ttls.AccessTokenTTL <= 0 {
			return fmt.Errorf("access_token_ttl must be > 0")
		}
		cfg.AccessTokenTTL = time.Duration(*ttls.AccessTokenTTL) * time.Second
	}
	if ttls.IDTokenTTL != nil {
		if *ttls.IDTokenTTL <= 0 {
			return fmt.Errorf("id_token_ttl must be > 0")
		}
		cfg.IDTokenTTL = time.Duration(*ttls.IDTokenTTL) * time.Second
	}
	if ttls.RefreshTokenTTL != nil {
		if *ttls.RefreshTokenTTL <= 0 {
			return fmt.Errorf("refresh_token_ttl must be > 0")
		}
		cfg.RefreshTokenTTL = time.Duration(*ttls.RefreshTokenTTL) * time.Second
	}
	p.issuer.SetTokenConfig(cfg)
	return nil
}

// issuerMinter adapts oidcengine.Issuer to the httpapi.TokenMinter interface.
// It converts between the oidc-package return type and httpapi.MintedTokens,
// avoiding a circular import between httpapi and oidc.
type issuerMinter struct {
	issuer *oidcengine.Issuer
}

func (m *issuerMinter) MintForUser(user domain.User, clientID string, scopes []string, expiresIn int) (httpapi.MintedTokens, error) {
	t, err := m.issuer.MintForUser(user, clientID, scopes, expiresIn)
	if err != nil {
		return httpapi.MintedTokens{}, err
	}
	return httpapi.MintedTokens{
		AccessToken: t.AccessToken,
		IDToken:     t.IDToken,
		ExpiresIn:   t.ExpiresIn,
	}, nil
}
