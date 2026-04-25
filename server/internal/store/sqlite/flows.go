package sqlite

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"furnace/server/internal/domain"
	"furnace/server/internal/store"
)

type FlowStore struct {
	db *sql.DB
}

func (s *Store) Flows() *FlowStore {
	return &FlowStore{db: s.db}
}

func (s *FlowStore) Create(flow domain.Flow) (domain.Flow, error) {
	scopesJSON, err := json.Marshal(flow.Scopes)
	if err != nil {
		return domain.Flow{}, fmt.Errorf("marshal flow scopes: %w", err)
	}
	var completedAt *string
	if flow.CompletedAt != nil {
		s := flow.CompletedAt.UTC().Format(time.RFC3339Nano)
		completedAt = &s
	}
	_, err = s.db.Exec(`
		INSERT INTO flows (
			id, user_id, state, scenario, attempts, error, protocol,
			client_id, redirect_uri, scopes_json, response_type, oauth_state,
			nonce, pkce_challenge, pkce_method, auth_code,
			totp_secret, sms_code, magic_link_token, magic_link_used,
			webauthn_challenge, webauthn_session,
			created_at, expires_at, completed_at
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		flow.ID, flow.UserID, flow.State, flow.Scenario, flow.Attempts, flow.Error, flow.Protocol,
		flow.ClientID, flow.RedirectURI, string(scopesJSON), flow.ResponseType, flow.OAuthState,
		flow.Nonce, flow.PKCEChallenge, flow.PKCEMethod, flow.AuthCode,
		flow.TOTPSecret, flow.SMSCode, flow.MagicLinkToken, flow.MagicLinkUsed,
		flow.WebAuthnChallenge, flow.WebAuthnSession,
		flow.CreatedAt.UTC().Format(time.RFC3339Nano),
		flow.ExpiresAt.UTC().Format(time.RFC3339Nano),
		completedAt,
	)
	if err != nil {
		return domain.Flow{}, fmt.Errorf("insert flow: %w", err)
	}
	return flow, nil
}

func (s *FlowStore) GetByID(id string) (domain.Flow, error) {
	row := s.db.QueryRow(`
		SELECT id, user_id, state, scenario, attempts, error, protocol,
		       client_id, redirect_uri, scopes_json, response_type, oauth_state,
		       nonce, pkce_challenge, pkce_method, auth_code,
		       totp_secret, sms_code, magic_link_token, magic_link_used,
		       webauthn_challenge, webauthn_session,
		       created_at, expires_at, completed_at
		FROM flows WHERE id = ?`, id)
	return scanFlow(row)
}

func (s *FlowStore) List() ([]domain.Flow, error) {
	rows, err := s.db.Query(`
		SELECT id, user_id, state, scenario, attempts, error, protocol,
		       client_id, redirect_uri, scopes_json, response_type, oauth_state,
		       nonce, pkce_challenge, pkce_method, auth_code,
		       totp_secret, sms_code, magic_link_token, magic_link_used,
		       webauthn_challenge, webauthn_session,
		       created_at, expires_at, completed_at
		FROM flows`)
	if err != nil {
		return nil, fmt.Errorf("list flows: %w", err)
	}
	defer rows.Close()

	out := make([]domain.Flow, 0)
	for rows.Next() {
		f, err := scanFlow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate flows: %w", err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *FlowStore) Update(flow domain.Flow) (domain.Flow, error) {
	scopesJSON, err := json.Marshal(flow.Scopes)
	if err != nil {
		return domain.Flow{}, fmt.Errorf("marshal flow scopes: %w", err)
	}
	var completedAt *string
	if flow.CompletedAt != nil {
		s := flow.CompletedAt.UTC().Format(time.RFC3339Nano)
		completedAt = &s
	}
	res, err := s.db.Exec(`
		UPDATE flows SET
			user_id=?, state=?, scenario=?, attempts=?, error=?, protocol=?,
			client_id=?, redirect_uri=?, scopes_json=?, response_type=?, oauth_state=?,
			nonce=?, pkce_challenge=?, pkce_method=?, auth_code=?,
			totp_secret=?, sms_code=?, magic_link_token=?, magic_link_used=?,
			webauthn_challenge=?, webauthn_session=?,
			created_at=?, expires_at=?, completed_at=?
		WHERE id=?`,
		flow.UserID, flow.State, flow.Scenario, flow.Attempts, flow.Error, flow.Protocol,
		flow.ClientID, flow.RedirectURI, string(scopesJSON), flow.ResponseType, flow.OAuthState,
		flow.Nonce, flow.PKCEChallenge, flow.PKCEMethod, flow.AuthCode,
		flow.TOTPSecret, flow.SMSCode, flow.MagicLinkToken, flow.MagicLinkUsed,
		flow.WebAuthnChallenge, flow.WebAuthnSession,
		flow.CreatedAt.UTC().Format(time.RFC3339Nano),
		flow.ExpiresAt.UTC().Format(time.RFC3339Nano),
		completedAt,
		flow.ID,
	)
	if err != nil {
		return domain.Flow{}, fmt.Errorf("update flow: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return domain.Flow{}, fmt.Errorf("check affected rows: %w", err)
	}
	if affected == 0 {
		return domain.Flow{}, store.ErrNotFound
	}
	return flow, nil
}

func (s *FlowStore) Delete(id string) error {
	res, err := s.db.Exec(`DELETE FROM flows WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete flow: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("check affected rows: %w", err)
	}
	if affected == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *FlowStore) DeleteExpired(now time.Time) (int, error) {
	res, err := s.db.Exec(`DELETE FROM flows WHERE expires_at < ?`, now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, fmt.Errorf("delete expired flows: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("check affected rows: %w", err)
	}
	return int(n), nil
}

func scanFlow(s scanner) (domain.Flow, error) {
	var f domain.Flow
	var scopesJSON string
	var createdAt, expiresAt string
	var completedAt sql.NullString

	err := s.Scan(
		&f.ID, &f.UserID, &f.State, &f.Scenario, &f.Attempts, &f.Error, &f.Protocol,
		&f.ClientID, &f.RedirectURI, &scopesJSON, &f.ResponseType, &f.OAuthState,
		&f.Nonce, &f.PKCEChallenge, &f.PKCEMethod, &f.AuthCode,
		&f.TOTPSecret, &f.SMSCode, &f.MagicLinkToken, &f.MagicLinkUsed,
		&f.WebAuthnChallenge, &f.WebAuthnSession,
		&createdAt, &expiresAt, &completedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return domain.Flow{}, store.ErrNotFound
		}
		return domain.Flow{}, fmt.Errorf("scan flow: %w", err)
	}

	if err := json.Unmarshal([]byte(scopesJSON), &f.Scopes); err != nil {
		return domain.Flow{}, fmt.Errorf("decode flow scopes: %w", err)
	}
	if f.Scopes == nil {
		f.Scopes = []string{}
	}

	if f.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt); err != nil {
		return domain.Flow{}, fmt.Errorf("parse flow created_at: %w", err)
	}
	if f.ExpiresAt, err = time.Parse(time.RFC3339Nano, expiresAt); err != nil {
		return domain.Flow{}, fmt.Errorf("parse flow expires_at: %w", err)
	}
	if completedAt.Valid && completedAt.String != "" {
		t, err := time.Parse(time.RFC3339Nano, completedAt.String)
		if err != nil {
			return domain.Flow{}, fmt.Errorf("parse flow completed_at: %w", err)
		}
		f.CompletedAt = &t
	}
	return f, nil
}
