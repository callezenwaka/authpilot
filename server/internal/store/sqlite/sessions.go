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

type SessionStore struct {
	db *sql.DB
}

func (s *Store) Sessions() *SessionStore {
	return &SessionStore{db: s.db}
}

func (s *SessionStore) Create(session domain.Session) (domain.Session, error) {
	eventsJSON, err := json.Marshal(session.Events)
	if err != nil {
		return domain.Session{}, fmt.Errorf("marshal session events: %w", err)
	}
	_, err = s.db.Exec(`
		INSERT INTO sessions (
			id, user_id, flow_id, protocol, provider, client_id,
			events_json, refresh_token, created_at, expires_at
		) VALUES (?,?,?,?,?,?,?,?,?,?)`,
		session.ID, session.UserID, session.FlowID, session.Protocol, session.Provider, session.ClientID,
		string(eventsJSON), session.RefreshToken,
		session.CreatedAt.UTC().Format(time.RFC3339Nano),
		session.ExpiresAt.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return domain.Session{}, fmt.Errorf("insert session: %w", err)
	}
	return session, nil
}

func (s *SessionStore) GetByID(id string) (domain.Session, error) {
	row := s.db.QueryRow(`
		SELECT id, user_id, flow_id, protocol, provider, client_id,
		       events_json, refresh_token, created_at, expires_at
		FROM sessions WHERE id = ?`, id)
	return scanSession(row)
}

func (s *SessionStore) GetByRefreshToken(token string) (domain.Session, error) {
	row := s.db.QueryRow(`
		SELECT id, user_id, flow_id, protocol, provider, client_id,
		       events_json, refresh_token, created_at, expires_at
		FROM sessions WHERE refresh_token = ?`, token)
	return scanSession(row)
}

func (s *SessionStore) List() ([]domain.Session, error) {
	rows, err := s.db.Query(`
		SELECT id, user_id, flow_id, protocol, provider, client_id,
		       events_json, refresh_token, created_at, expires_at
		FROM sessions`)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	defer rows.Close()

	out := make([]domain.Session, 0)
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sessions: %w", err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *SessionStore) Update(session domain.Session) (domain.Session, error) {
	eventsJSON, err := json.Marshal(session.Events)
	if err != nil {
		return domain.Session{}, fmt.Errorf("marshal session events: %w", err)
	}
	res, err := s.db.Exec(`
		UPDATE sessions SET
			user_id=?, flow_id=?, protocol=?, provider=?, client_id=?,
			events_json=?, refresh_token=?, created_at=?, expires_at=?
		WHERE id=?`,
		session.UserID, session.FlowID, session.Protocol, session.Provider, session.ClientID,
		string(eventsJSON), session.RefreshToken,
		session.CreatedAt.UTC().Format(time.RFC3339Nano),
		session.ExpiresAt.UTC().Format(time.RFC3339Nano),
		session.ID,
	)
	if err != nil {
		return domain.Session{}, fmt.Errorf("update session: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return domain.Session{}, fmt.Errorf("check affected rows: %w", err)
	}
	if affected == 0 {
		return domain.Session{}, store.ErrNotFound
	}
	return session, nil
}

func (s *SessionStore) Delete(id string) error {
	res, err := s.db.Exec(`DELETE FROM sessions WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
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

func (s *SessionStore) DeleteExpired(now time.Time) (int, error) {
	res, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at < ?`, now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, fmt.Errorf("delete expired sessions: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("check affected rows: %w", err)
	}
	return int(n), nil
}

func scanSession(s scanner) (domain.Session, error) {
	var sess domain.Session
	var eventsJSON string
	var createdAt, expiresAt string

	err := s.Scan(
		&sess.ID, &sess.UserID, &sess.FlowID, &sess.Protocol, &sess.Provider, &sess.ClientID,
		&eventsJSON, &sess.RefreshToken, &createdAt, &expiresAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return domain.Session{}, store.ErrNotFound
		}
		return domain.Session{}, fmt.Errorf("scan session: %w", err)
	}

	if err := json.Unmarshal([]byte(eventsJSON), &sess.Events); err != nil {
		return domain.Session{}, fmt.Errorf("decode session events: %w", err)
	}
	if sess.Events == nil {
		sess.Events = []domain.SessionEvent{}
	}

	if sess.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt); err != nil {
		return domain.Session{}, fmt.Errorf("parse session created_at: %w", err)
	}
	if sess.ExpiresAt, err = time.Parse(time.RFC3339Nano, expiresAt); err != nil {
		return domain.Session{}, fmt.Errorf("parse session expires_at: %w", err)
	}
	return sess, nil
}
