// Package authevents defines the authentication event stream — a distinct sink
// for intrusion signals (failed login, MFA mismatch, WebAuthn failure, bad API
// key, rate-limit abuse). This stream is separate from the admin audit log
// (store.AuditStore) and from any future OPA decision log.
package authevents

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Event type constants.
const (
	TypeLoginFailed    = "login_failed"    // conclusive auth denial (flow denied / error)
	TypeMFAMismatch    = "mfa_mismatch"    // MFA code rejected
	TypeWebAuthnFailed = "webauthn_failed" // passkey assertion verification failed
	TypeKeyRejected    = "key_rejected"    // API key missing or not recognised
	TypeSignupAbuse    = "signup_abuse"    // rate-limit trip on a request path
)

// Event is the canonical auth event schema. All fields are JSON-serialised;
// omitempty fields are omitted when zero so the schema stays stable across
// additions.
type Event struct {
	Time   time.Time      `json:"time"`
	Type   string         `json:"type"`
	IP     string         `json:"ip,omitempty"`
	UserID string         `json:"user_id,omitempty"`
	FlowID string         `json:"flow_id,omitempty"`
	Meta   map[string]any `json:"meta,omitempty"`
}

// Sink receives auth events.
type Sink interface {
	Emit(e Event)
}

// noopSink discards every event. Used in tests and when auth event logging is
// not configured.
type noopSink struct{}

func (noopSink) Emit(Event) {}

// Noop returns a Sink that silently discards all events.
func Noop() Sink { return noopSink{} }

// writerSink writes one JSON line per event to an io.Writer.
// Concurrent calls are serialised by mu.
type writerSink struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func (s *writerSink) Emit(e Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.enc.Encode(e) // best-effort; never block callers on I/O error
}

// NewWriterSink returns a Sink that writes JSON lines to w.
func NewWriterSink(w io.Writer) Sink {
	return &writerSink{enc: json.NewEncoder(w)}
}

// NewSink creates a production Sink from a destination string.
//
//   - "" or "stderr" → os.Stderr (default for local and Docker)
//   - any other value → file path, opened for append (created if missing, mode 0600)
//
// Returns the Sink, a Closer that releases the underlying file (if any), and
// any error encountered opening the file.
func NewSink(dest string) (Sink, io.Closer, error) {
	if dest == "" || dest == "stderr" {
		return NewWriterSink(os.Stderr), io.NopCloser(nil), nil
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("auth event log %q: %w", dest, err)
	}
	return NewWriterSink(f), f, nil
}
