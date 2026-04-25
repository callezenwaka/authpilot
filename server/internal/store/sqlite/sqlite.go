package sqlite

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
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
			email TEXT NOT NULL,
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
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("sqlite migration failed: %w", err)
		}
	}
	return nil
}
