package sqlite

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

type Store struct {
	db     *sql.DB
	signer *policySigner
}

func New(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create sqlite directory: %w", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}

	store := &Store{db: db}
	if err := store.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	signer, err := loadOrCreateSigner(db)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("policy signer: %w", err)
	}
	store.signer = signer
	return store, nil
}

func (s *Store) Ping() error {
	return s.db.Ping()
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			email TEXT NOT NULL UNIQUE,
			display_name TEXT NOT NULL,
			groups_json TEXT NOT NULL,
			mfa_method TEXT NOT NULL,
			next_flow TEXT NOT NULL,
			claims_json TEXT,
			phone_number TEXT,
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS groups (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			display_name TEXT NOT NULL,
			member_ids_json TEXT NOT NULL,
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS flows (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL DEFAULT '',
			state TEXT NOT NULL,
			scenario TEXT NOT NULL DEFAULT '',
			attempts INTEGER NOT NULL DEFAULT 0,
			error TEXT NOT NULL DEFAULT '',
			protocol TEXT NOT NULL DEFAULT '',
			client_id TEXT NOT NULL DEFAULT '',
			redirect_uri TEXT NOT NULL DEFAULT '',
			scopes_json TEXT NOT NULL DEFAULT '[]',
			response_type TEXT NOT NULL DEFAULT '',
			oauth_state TEXT NOT NULL DEFAULT '',
			nonce TEXT NOT NULL DEFAULT '',
			pkce_challenge TEXT NOT NULL DEFAULT '',
			pkce_method TEXT NOT NULL DEFAULT '',
			auth_code TEXT NOT NULL DEFAULT '',
			totp_secret TEXT NOT NULL DEFAULT '',
			sms_code TEXT NOT NULL DEFAULT '',
			magic_link_token TEXT NOT NULL DEFAULT '',
			magic_link_used INTEGER NOT NULL DEFAULT 0,
			webauthn_challenge TEXT NOT NULL DEFAULT '',
			webauthn_session TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			expires_at TEXT NOT NULL,
			completed_at TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL DEFAULT '',
			flow_id TEXT NOT NULL DEFAULT '',
			protocol TEXT NOT NULL DEFAULT '',
			provider TEXT NOT NULL DEFAULT '',
			client_id TEXT NOT NULL DEFAULT '',
			events_json TEXT NOT NULL DEFAULT '[]',
			refresh_token TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			expires_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS opa_policies (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			version TEXT NOT NULL,
			content TEXT NOT NULL,
			content_hash TEXT NOT NULL,
			active INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL,
			activated_at TEXT
		);`,
		`CREATE UNIQUE INDEX IF NOT EXISTS opa_policies_name_version ON opa_policies (name, version);`,
		`CREATE TABLE IF NOT EXISTS api_keys (
			id TEXT PRIMARY KEY,
			label TEXT NOT NULL,
			key_hash TEXT NOT NULL UNIQUE,
			scopes_json TEXT NOT NULL DEFAULT '[]',
			created_at TEXT NOT NULL,
			revoked_at TEXT,
			last_used_at TEXT
		);`,
		// furnace_settings is a generic KV store for internal config (e.g. signing keys).
		`CREATE TABLE IF NOT EXISTS furnace_settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);`,
		// audit_log is append-only; no UPDATE or DELETE are ever issued by the store layer.
		// chain_hash links each row to all preceding rows for tamper-evidence.
		`CREATE TABLE IF NOT EXISTS audit_log (
			id TEXT PRIMARY KEY,
			timestamp TEXT NOT NULL,
			event_json TEXT NOT NULL,
			chain_hash TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS audit_log_timestamp ON audit_log (timestamp);`,
		`CREATE TABLE IF NOT EXISTS admins (
			id TEXT PRIMARY KEY,
			username TEXT NOT NULL UNIQUE,
			display_name TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			active INTEGER NOT NULL DEFAULT 1,
			created_at TEXT NOT NULL
		);`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("sqlite migration failed: %w", err)
		}
	}
	// Additive column migrations — idempotent via "duplicate column" error suppression.
	addCols := []string{
		`ALTER TABLE users ADD COLUMN password_hash TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE users ADD COLUMN active INTEGER NOT NULL DEFAULT 1`,
		`ALTER TABLE opa_policies ADD COLUMN signature TEXT NOT NULL DEFAULT ''`,
	}
	for _, stmt := range addCols {
		if _, err := s.db.Exec(stmt); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
			return fmt.Errorf("sqlite column migration failed: %w", err)
		}
	}
	return nil
}
