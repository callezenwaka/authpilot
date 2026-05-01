package sqlite

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"furnace/server/internal/domain"
	"furnace/server/internal/store"
)

// SQLiteAuditStore is an append-only audit log backed by SQLite.
// Each inserted row carries a chain_hash computed as:
//
//	hex(sha256(prev_chain_hash + event_json))
//
// This forms a tamper-evident chain: any post-hoc modification to a stored
// row (or to chain_hash itself) will cause Verify to report the mismatch.
type SQLiteAuditStore struct {
	db *sql.DB
}

// Audit returns a SQLiteAuditStore for this Store.
func (s *Store) Audit() *SQLiteAuditStore {
	return &SQLiteAuditStore{db: s.db}
}

func auditChainHash(prevHash, eventJSON string) string {
	h := sha256.Sum256([]byte(prevHash + eventJSON))
	return hex.EncodeToString(h[:])
}

// Append inserts an event into the append-only audit_log table and computes
// a chain_hash that links this row to all preceding rows.
// Errors are silently discarded; audit failures must not block the caller.
func (s *SQLiteAuditStore) Append(event domain.AuditEvent) {
	data, err := json.Marshal(event)
	if err != nil {
		return
	}
	eventJSON := string(data)

	var prevHash string
	_ = s.db.QueryRow(`SELECT chain_hash FROM audit_log ORDER BY rowid DESC LIMIT 1`).Scan(&prevHash)

	chainHash := auditChainHash(prevHash, eventJSON)

	_, _ = s.db.Exec(
		`INSERT OR IGNORE INTO audit_log (id, timestamp, event_json, chain_hash) VALUES (?, ?, ?, ?)`,
		event.ID,
		event.Timestamp.UTC().Format(time.RFC3339Nano),
		eventJSON,
		chainHash,
	)
}

// List returns events in insertion order, optionally filtered by event type or timestamp.
func (s *SQLiteAuditStore) List(filter store.AuditFilter) []domain.AuditEvent {
	q := `SELECT event_json FROM audit_log`
	var args []any
	if !filter.Since.IsZero() {
		q += ` WHERE timestamp >= ?`
		args = append(args, filter.Since.UTC().Format(time.RFC3339Nano))
	}
	q += ` ORDER BY rowid ASC`

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var events []domain.AuditEvent
	for rows.Next() {
		var eventJSON string
		if err := rows.Scan(&eventJSON); err != nil {
			continue
		}
		var e domain.AuditEvent
		if err := json.Unmarshal([]byte(eventJSON), &e); err != nil {
			continue
		}
		if filter.EventType != "" && e.EventType != filter.EventType {
			continue
		}
		events = append(events, e)
	}
	return events
}

// Verify walks every row in insertion order and recomputes the chain hash.
// Returns ok=false and the first offending event ID when a mismatch is found.
func (s *SQLiteAuditStore) Verify() (store.AuditVerifyResult, error) {
	rows, err := s.db.Query(`SELECT id, event_json, chain_hash FROM audit_log ORDER BY rowid ASC`)
	if err != nil {
		return store.AuditVerifyResult{}, fmt.Errorf("query audit_log: %w", err)
	}
	defer rows.Close()

	var prevHash string
	checked := 0
	for rows.Next() {
		var id, eventJSON, storedHash string
		if err := rows.Scan(&id, &eventJSON, &storedHash); err != nil {
			return store.AuditVerifyResult{}, fmt.Errorf("scan audit row: %w", err)
		}
		expected := auditChainHash(prevHash, eventJSON)
		if expected != storedHash {
			return store.AuditVerifyResult{
				OK:       false,
				Checked:  checked,
				BrokenAt: id,
				Message:  fmt.Sprintf("hash mismatch at event %s", id),
			}, nil
		}
		prevHash = storedHash
		checked++
	}
	return store.AuditVerifyResult{OK: true, Checked: checked, Message: "chain intact"}, nil
}
