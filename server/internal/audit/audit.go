// Package audit defines audit event types and helpers for emitting them.
package audit

import (
	"fmt"
	"time"

	"authpilot/server/internal/domain"
	"authpilot/server/internal/store"
)

// Event type constants — dot-separated resource.action.
const (
	EventUserCreated   = "user.created"
	EventUserUpdated   = "user.updated"
	EventUserDeleted   = "user.deleted"
	EventFlowCreated   = "flow.created"
	EventFlowComplete  = "flow.complete"
	EventFlowDenied    = "flow.denied"
	EventFlowError     = "flow.error"
	EventSessionIssued = "session.issued"
	EventSessionExpired = "session.expired"
)

var counter uint64

// Emit appends a new AuditEvent. Silently ignores a nil store so callers
// do not need to guard every call site.
func Emit(s store.AuditStore, eventType, actor, resourceID string, meta map[string]any) {
	if s == nil {
		return
	}
	counter++
	id := fmt.Sprintf("aud_%d_%d", time.Now().UnixNano(), counter)
	s.Append(domain.AuditEvent{
		ID:         id,
		Timestamp:  time.Now().UTC(),
		EventType:  eventType,
		Actor:      actor,
		ResourceID: resourceID,
		Metadata:   meta,
	})
}
