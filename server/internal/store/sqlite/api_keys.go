package sqlite

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"furnace/server/internal/domain"
	"furnace/server/internal/store"
)

type APIKeyStore struct {
	db *sql.DB
}

func (s *Store) APIKeys() *APIKeyStore {
	return &APIKeyStore{db: s.db}
}

func (s *APIKeyStore) Create(k domain.APIKey) (domain.APIKey, error) {
	scopesJSON, err := json.Marshal(k.Scopes)
	if err != nil {
		return domain.APIKey{}, fmt.Errorf("marshal scopes: %w", err)
	}
	_, err = s.db.Exec(`
		INSERT INTO api_keys (id, label, key_hash, scopes_json, created_at)
		VALUES (?, ?, ?, ?, ?)
	`, k.ID, k.Label, k.KeyHash, string(scopesJSON), k.CreatedAt.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return domain.APIKey{}, fmt.Errorf("insert api key: %w", err)
	}
	return k, nil
}

func (s *APIKeyStore) GetByID(id string) (domain.APIKey, error) {
	row := s.db.QueryRow(`
		SELECT id, label, key_hash, scopes_json, created_at, revoked_at, last_used_at
		FROM api_keys WHERE id = ?
	`, id)
	return scanAPIKey(row)
}

func (s *APIKeyStore) GetByHash(hash string) (domain.APIKey, error) {
	row := s.db.QueryRow(`
		SELECT id, label, key_hash, scopes_json, created_at, revoked_at, last_used_at
		FROM api_keys WHERE key_hash = ?
	`, hash)
	k, err := scanAPIKey(row)
	if err != nil {
		return domain.APIKey{}, fmt.Errorf("get api key by hash: %w", err)
	}
	return k, nil
}

func (s *APIKeyStore) List() ([]domain.APIKey, error) {
	rows, err := s.db.Query(`
		SELECT id, label, key_hash, scopes_json, created_at, revoked_at, last_used_at
		FROM api_keys ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("list api keys: %w", err)
	}
	defer rows.Close()

	keys := make([]domain.APIKey, 0)
	for rows.Next() {
		k, err := scanAPIKey(rows)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

func (s *APIKeyStore) Revoke(id string, at time.Time) error {
	res, err := s.db.Exec(`
		UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL
	`, at.UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return fmt.Errorf("revoke api key: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		// Either not found or already revoked — treat as not found.
		return store.ErrNotFound
	}
	return nil
}

func (s *APIKeyStore) UpdateLastUsed(id string, at time.Time) error {
	_, err := s.db.Exec(`
		UPDATE api_keys SET last_used_at = ? WHERE id = ?
	`, at.UTC().Format(time.RFC3339Nano), id)
	return err
}

func scanAPIKey(s scanner) (domain.APIKey, error) {
	var k domain.APIKey
	var scopesJSON, createdAt string
	var revokedAt, lastUsedAt sql.NullString

	err := s.Scan(&k.ID, &k.Label, &k.KeyHash, &scopesJSON,
		&createdAt, &revokedAt, &lastUsedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return domain.APIKey{}, store.ErrNotFound
		}
		return domain.APIKey{}, fmt.Errorf("scan api key: %w", err)
	}

	if err := json.Unmarshal([]byte(scopesJSON), &k.Scopes); err != nil {
		k.Scopes = []string{}
	}
	if t, err := time.Parse(time.RFC3339Nano, createdAt); err == nil {
		k.CreatedAt = t.UTC()
	}
	if revokedAt.Valid {
		if t, err := time.Parse(time.RFC3339Nano, revokedAt.String); err == nil {
			tc := t.UTC()
			k.RevokedAt = &tc
		}
	}
	if lastUsedAt.Valid {
		if t, err := time.Parse(time.RFC3339Nano, lastUsedAt.String); err == nil {
			tc := t.UTC()
			k.LastUsedAt = &tc
		}
	}
	return k, nil
}
