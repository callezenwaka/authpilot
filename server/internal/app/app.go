package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"authpilot/server/internal/config"
	"authpilot/server/internal/httpapi"
	oidcengine "authpilot/server/internal/oidc"
	"authpilot/server/internal/store"
	"authpilot/server/internal/store/memory"
	sqliteStore "authpilot/server/internal/store/sqlite"
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

	httpBaseURL := "http://localhost" + cfg.HTTPAddr
	router := httpapi.NewRouter(httpapi.Dependencies{
		Users:    users,
		Groups:   groups,
		Flows:    flows,
		Sessions: sessions,
		APIKey:   cfg.APIKey,
		BaseURL:  httpBaseURL,
	})

	httpServer := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
	}

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

	protocolServer := &http.Server{
		Addr:              cfg.ProtocolAddr,
		Handler:           oidcRouter,
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
