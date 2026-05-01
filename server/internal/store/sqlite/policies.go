package sqlite

import (
	"database/sql"
	"fmt"
	"time"

	"furnace/server/internal/domain"
	"furnace/server/internal/store"
)

type PolicyStore struct {
	db     *sql.DB
	signer *policySigner
}

func (s *PolicyStore) Create(p domain.Policy) (domain.Policy, error) {
	p.CreatedAt = p.CreatedAt.UTC()

	_, err := s.db.Exec(`
		INSERT INTO opa_policies (id, name, version, content, content_hash, signature, active, created_at, activated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, p.ID, p.Name, p.Version, p.Content, p.ContentHash, p.Signature,
		boolInt(p.Active), p.CreatedAt.Format(time.RFC3339Nano), nullTime(p.ActivatedAt))
	if err != nil {
		return domain.Policy{}, fmt.Errorf("insert policy: %w", err)
	}
	return p, nil
}

func (s *PolicyStore) GetByID(id string) (domain.Policy, error) {
	row := s.db.QueryRow(`
		SELECT id, name, version, content, content_hash, signature, active, created_at, activated_at
		FROM opa_policies WHERE id = ?
	`, id)
	return scanPolicy(row)
}

func (s *PolicyStore) GetByName(name string) (domain.Policy, error) {
	row := s.db.QueryRow(`
		SELECT id, name, version, content, content_hash, signature, active, created_at, activated_at
		FROM opa_policies WHERE name = ? AND active = 1
	`, name)
	p, err := scanPolicy(row)
	if err != nil {
		return domain.Policy{}, fmt.Errorf("get active policy %q: %w", name, err)
	}
	// Verify signature when present — guards against DB-level tampering.
	if p.Signature != "" && s.signer != nil {
		if !s.signer.verify(p.ContentHash, p.Signature) {
			return domain.Policy{}, store.ErrPolicyTampered
		}
	}
	return p, nil
}

func (s *PolicyStore) List() ([]domain.Policy, error) {
	rows, err := s.db.Query(`
		SELECT id, name, version, content, content_hash, signature, active, created_at, activated_at
		FROM opa_policies ORDER BY name, created_at
	`)
	if err != nil {
		return nil, fmt.Errorf("list policies: %w", err)
	}
	defer rows.Close()

	policies := make([]domain.Policy, 0)
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		policies = append(policies, p)
	}
	return policies, rows.Err()
}

func (s *PolicyStore) Activate(id string, at time.Time) error {
	// Fetch name and content_hash so we can sign the specific content being activated.
	var name, contentHash string
	if err := s.db.QueryRow(`SELECT name, content_hash FROM opa_policies WHERE id = ?`, id).Scan(&name, &contentHash); err != nil {
		if err == sql.ErrNoRows {
			return store.ErrNotFound
		}
		return fmt.Errorf("activate policy: lookup: %w", err)
	}

	// Sign the content_hash — attests that this exact content was reviewed and activated.
	sig := ""
	if s.signer != nil {
		sig = s.signer.sign(contentHash)
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("activate policy: begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err := tx.Exec(`UPDATE opa_policies SET active = 0, activated_at = NULL, signature = '' WHERE name = ?`, name); err != nil {
		return fmt.Errorf("activate policy: deactivate siblings: %w", err)
	}
	if _, err := tx.Exec(`UPDATE opa_policies SET active = 1, activated_at = ?, signature = ? WHERE id = ?`,
		at.UTC().Format(time.RFC3339Nano), sig, id); err != nil {
		return fmt.Errorf("activate policy: set active: %w", err)
	}
	return tx.Commit()
}

func (s *PolicyStore) Delete(id string) error {
	res, err := s.db.Exec(`DELETE FROM opa_policies WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete policy: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// ---- helpers ----

func scanPolicy(s scanner) (domain.Policy, error) {
	var p domain.Policy
	var activeInt int
	var createdAt string
	var activatedAt sql.NullString

	err := s.Scan(&p.ID, &p.Name, &p.Version, &p.Content, &p.ContentHash, &p.Signature,
		&activeInt, &createdAt, &activatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return domain.Policy{}, store.ErrNotFound
		}
		return domain.Policy{}, fmt.Errorf("scan policy: %w", err)
	}

	p.Active = activeInt == 1
	if t, err := time.Parse(time.RFC3339Nano, createdAt); err == nil {
		p.CreatedAt = t.UTC()
	}
	if activatedAt.Valid {
		if t, err := time.Parse(time.RFC3339Nano, activatedAt.String); err == nil {
			tc := t.UTC()
			p.ActivatedAt = &tc
		}
	}
	return p, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().Format(time.RFC3339Nano)
}
