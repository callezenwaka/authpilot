package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"authpilot/server/internal/config"
	"authpilot/server/internal/domain"
	"authpilot/server/internal/httpapi"
	oidcengine "authpilot/server/internal/oidc"
	samlengine "authpilot/server/internal/saml"
	"authpilot/server/internal/scim"
	"authpilot/server/internal/store"
	"authpilot/server/internal/store/memory"
	sqliteStore "authpilot/server/internal/store/sqlite"
	wsfedengine "authpilot/server/internal/wsfed"
)

type App struct {
	cfg    config.Config
	logger *slog.Logger

	users    store.UserStore
	groups   store.GroupStore
	flows    store.FlowStore
	sessions store.SessionStore

	httpServer     *http.Server
	protocolServer *http.Server
	closers        []func() error
	cleanupDone    chan struct{}
}

func New(cfg config.Config, logger *slog.Logger) (*App, error) {
	var users store.UserStore
	var groups store.GroupStore
	closers := make([]func() error, 0)

	if cfg.Persistence.Enabled {
		sqlite, err := sqliteStore.New(cfg.Persistence.SQLitePath)
		if err != nil {
			return nil, fmt.Errorf("initialize sqlite persistence: %w", err)
		}
		users = sqlite.Users()
		groups = sqlite.Groups()
		closers = append(closers, sqlite.Close)
	} else {
		users = memory.NewUserStore()
		groups = memory.NewGroupStore()
	}

	flows := memory.NewFlowStore()
	sessions := memory.NewSessionStore()

	if err := seedUsers(users, cfg.SeedUsers); err != nil {
		return nil, fmt.Errorf("seed users: %w", err)
	}

	httpBaseURL := "http://localhost" + cfg.HTTPAddr
	km, err := oidcengine.NewKeyManager()
	if err != nil {
		return nil, fmt.Errorf("initialize oidc key manager: %w", err)
	}
	tokenCfg := oidcengine.TokenConfig{
		AccessTokenTTL:  cfg.OIDC.AccessTokenTTL,
		IDTokenTTL:      cfg.OIDC.IDTokenTTL,
		RefreshTokenTTL: cfg.OIDC.RefreshTokenTTL,
	}
	issuer := oidcengine.NewIssuer(km, tokenCfg, cfg.OIDC.IssuerURL)

	scimRouter := scim.NewRouter(scim.RouterDeps{
		Users:  users,
		Groups: groups,
	})
	cp := &issuerConfigPatcher{issuer: issuer}
	router := httpapi.NewRouter(httpapi.Dependencies{
		Users:         users,
		Groups:        groups,
		Flows:         flows,
		Sessions:      sessions,
		APIKey:        cfg.APIKey,
		SCIMKey:       cfg.SCIMKey,
		BaseURL:       httpBaseURL,
		RateLimit:     cfg.RateLimit,
		SCIMRouter:    scimRouter,
		TokenMinter:   &issuerMinter{issuer: issuer},
		ConfigPatcher: cp,
	})

	httpServer := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
	}

	loginURL := "http://localhost" + cfg.HTTPAddr + "/login"
	oidcRouter := oidcengine.NewRouter(oidcengine.RouterDeps{
		Flows:     flows,
		Users:     users,
		Sessions:  sessions,
		KeyMgr:    km,
		Issuer:    issuer,
		IssuerURL: cfg.OIDC.IssuerURL,
		LoginURL:  loginURL,
	})

	samlCertMgr, err := samlengine.NewCertManagerFromPath(cfg.SAML.CertDir)
	if err != nil {
		return nil, fmt.Errorf("initialize saml cert manager: %w", err)
	}
	protocolBase := "http://localhost" + cfg.ProtocolAddr
	samlEntityID := cfg.SAML.EntityID
	if samlEntityID == "" {
		samlEntityID = protocolBase
	}
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
		Handler:           protocolMux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	return &App{
		cfg:            cfg,
		logger:         logger,
		users:          users,
		groups:         groups,
		flows:          flows,
		sessions:       sessions,
		httpServer:     httpServer,
		protocolServer: protocolServer,
		closers:        closers,
		cleanupDone:    make(chan struct{}),
	}, nil
}

func (a *App) Start(ctx context.Context) error {
	a.logger.Info("authpilot starting",
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
