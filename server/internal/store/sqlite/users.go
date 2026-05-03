package sqlite

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"furnace/server/internal/domain"
	"furnace/server/internal/store"
)

type UserStore struct {
	db *sql.DB
}

func (s *Store) Policies() *PolicyStore {
	return &PolicyStore{db: s.db, signer: s.signer}
}

func (s *Store) Users() *UserStore {
	return &UserStore{db: s.db}
}

func (s *UserStore) Create(user domain.User) (domain.User, error) {
	groupsJSON, claimsJSON, err := userJSON(user)
	if err != nil {
		return domain.User{}, err
	}

	_, err = s.db.Exec(`
		INSERT INTO users (id, email, display_name, groups_json, mfa_method, next_flow, claims_json, phone_number, password_hash, active, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, user.ID, user.Email, user.DisplayName, groupsJSON, user.MFAMethod, user.NextFlow, claimsJSON, user.PhoneNumber, user.PasswordHash, boolToInt(user.Active), user.CreatedAt.UTC().Format(time.RFC3339Nano))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed: users.email") {
			return domain.User{}, store.ErrConflict
		}
		return domain.User{}, fmt.Errorf("insert user: %w", err)
	}
	return user, nil
}

func (s *UserStore) GetByID(id string) (domain.User, error) {
	row := s.db.QueryRow(`
		SELECT id, email, display_name, groups_json, mfa_method, next_flow, claims_json, phone_number, password_hash, active, created_at
		FROM users
		WHERE id = ?
	`, id)
	return scanUser(row)
}

func (s *UserStore) List() ([]domain.User, error) {
	rows, err := s.db.Query(`
		SELECT id, email, display_name, groups_json, mfa_method, next_flow, claims_json, phone_number, password_hash, active, created_at
		FROM users
	`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	users := make([]domain.User, 0)
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate users: %w", err)
	}

	sort.Slice(users, func(i, j int) bool { return users[i].ID < users[j].ID })
	return users, nil
}

func (s *UserStore) Update(user domain.User) (domain.User, error) {
	groupsJSON, claimsJSON, err := userJSON(user)
	if err != nil {
		return domain.User{}, err
	}

	res, err := s.db.Exec(`
		UPDATE users
		SET email = ?, display_name = ?, groups_json = ?, mfa_method = ?, next_flow = ?, claims_json = ?, phone_number = ?, password_hash = ?, active = ?, created_at = ?
		WHERE id = ?
	`, user.Email, user.DisplayName, groupsJSON, user.MFAMethod, user.NextFlow, claimsJSON, user.PhoneNumber, user.PasswordHash, boolToInt(user.Active), user.CreatedAt.UTC().Format(time.RFC3339Nano), user.ID)
	if err != nil {
		return domain.User{}, fmt.Errorf("update user: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return domain.User{}, fmt.Errorf("check affected rows: %w", err)
	}
	if affected == 0 {
		return domain.User{}, store.ErrNotFound
	}
	return user, nil
}

func (s *UserStore) Delete(id string) error {
	res, err := s.db.Exec(`DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
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

func userJSON(user domain.User) (groupsJSON string, claimsJSON string, err error) {
	groupsBytes, err := json.Marshal(user.Groups)
	if err != nil {
		return "", "", fmt.Errorf("marshal user groups: %w", err)
	}
	groupsJSON = string(groupsBytes)

	if user.Claims == nil {
		return groupsJSON, "", nil
	}

	claimsBytes, err := json.Marshal(user.Claims)
	if err != nil {
		return "", "", fmt.Errorf("marshal user claims: %w", err)
	}
	claimsJSON = string(claimsBytes)
	return groupsJSON, claimsJSON, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanUser(s scanner) (domain.User, error) {
	var user domain.User
	var groupsJSON string
	var claimsJSON sql.NullString
	var activeInt int
	var createdAt string

	err := s.Scan(
		&user.ID,
		&user.Email,
		&user.DisplayName,
		&groupsJSON,
		&user.MFAMethod,
		&user.NextFlow,
		&claimsJSON,
		&user.PhoneNumber,
		&user.PasswordHash,
		&activeInt,
		&createdAt,
	)
	user.Active = activeInt != 0
	if err != nil {
		if err == sql.ErrNoRows {
			return domain.User{}, store.ErrNotFound
		}
		return domain.User{}, fmt.Errorf("scan user: %w", err)
	}

	if err := json.Unmarshal([]byte(groupsJSON), &user.Groups); err != nil {
		return domain.User{}, fmt.Errorf("decode user groups: %w", err)
	}

	if claimsJSON.Valid && claimsJSON.String != "" {
		if err := json.Unmarshal([]byte(claimsJSON.String), &user.Claims); err != nil {
			return domain.User{}, fmt.Errorf("decode user claims: %w", err)
		}
	}

	parsed, err := time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return domain.User{}, fmt.Errorf("parse user created_at: %w", err)
	}
	user.CreatedAt = parsed

	return user, nil
}
