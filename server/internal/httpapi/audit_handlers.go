package httpapi

import (
	"net/http"
	"time"

	auditpkg "furnace/server/internal/audit"
	"furnace/server/internal/domain"
	"furnace/server/internal/store"
)

func auditListHandler(as store.AuditStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if as == nil {
			writeJSON(w, http.StatusOK, []domain.AuditEvent{})
			return
		}
		filter := store.AuditFilter{
			EventType: r.URL.Query().Get("event_type"),
		}
		if s := r.URL.Query().Get("since"); s != "" {
			t, err := time.Parse(time.RFC3339, s)
			if err != nil {
				writeAPIError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "since must be RFC3339", false)
				return
			}
			filter.Since = t
		}
		events := as.List(filter)
		if events == nil {
			events = []domain.AuditEvent{}
		}
		writeJSON(w, http.StatusOK, events)
	}
}

// auditVerifyHandler walks the tamper-evident hash chain and reports whether
// every stored event hashes correctly to the next. Returns 200 when intact,
// 409 when a mismatch is detected.
func auditVerifyHandler(as store.AuditStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if as == nil {
			writeAPIError(w, r, http.StatusNotImplemented, "NOT_IMPLEMENTED", "audit store not configured", false)
			return
		}
		result, err := as.Verify()
		if err != nil {
			writeAPIError(w, r, http.StatusInternalServerError, "VERIFY_FAILED", err.Error(), false)
			return
		}
		status := http.StatusOK
		if !result.OK {
			status = http.StatusConflict
		}
		writeJSON(w, status, result)
	}
}

func auditExportHandler(as store.AuditStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if as == nil {
			writeAPIError(w, r, http.StatusNotImplemented, "NOT_IMPLEMENTED", "audit store not configured", false)
			return
		}
		rawFormat := r.URL.Query().Get("format")
		if rawFormat == "" {
			writeAPIError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "format is required (json-nd, cef, syslog)", false)
			return
		}
		f, err := auditpkg.ParseFormat(rawFormat)
		if err != nil {
			writeAPIError(w, r, http.StatusBadRequest, "INVALID_FORMAT", err.Error(), false)
			return
		}
		events := as.List(store.AuditFilter{})
		data, err := auditpkg.Export(events, f)
		if err != nil {
			writeAPIError(w, r, http.StatusInternalServerError, "EXPORT_FAILED", err.Error(), false)
			return
		}
		w.Header().Set("Content-Type", auditpkg.ContentType(f))
		w.Header().Set("Content-Disposition", `attachment; filename="`+auditpkg.Filename(f)+`"`)
		_, _ = w.Write(data)
	}
}
