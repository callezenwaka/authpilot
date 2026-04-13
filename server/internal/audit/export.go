package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"authpilot/server/internal/domain"
)

// Format identifies a supported audit export format.
type Format int

const (
	FormatJSONND  Format = iota // JSON-ND (newline-delimited JSON) for Splunk / Elastic
	FormatCEF                   // ArcSight Common Event Format
	FormatSyslog                // RFC 5424 syslog
)

// ParseFormat maps a string to a Format.
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "json", "json-nd", "jsonnd":
		return FormatJSONND, nil
	case "cef":
		return FormatCEF, nil
	case "syslog":
		return FormatSyslog, nil
	default:
		return 0, fmt.Errorf("unknown audit format %q; supported: json-nd, cef, syslog", s)
	}
}

// ContentType returns the MIME type for the given format.
func ContentType(f Format) string {
	switch f {
	case FormatCEF:
		return "text/plain; charset=utf-8"
	case FormatSyslog:
		return "text/plain; charset=utf-8"
	default:
		return "application/x-ndjson"
	}
}

// Filename returns a suggested download filename.
func Filename(f Format) string {
	ts := time.Now().UTC().Format("20060102-150405")
	switch f {
	case FormatCEF:
		return "audit-" + ts + ".cef"
	case FormatSyslog:
		return "audit-" + ts + ".log"
	default:
		return "audit-" + ts + ".jsonnd"
	}
}

// Export serialises events in the requested format.
func Export(events []domain.AuditEvent, f Format) ([]byte, error) {
	switch f {
	case FormatCEF:
		return exportCEF(events)
	case FormatSyslog:
		return exportSyslog(events)
	default:
		return exportJSONND(events)
	}
}

// ---------------------------------------------------------------------------
// JSON-ND
// ---------------------------------------------------------------------------

func exportJSONND(events []domain.AuditEvent) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, e := range events {
		if err := enc.Encode(e); err != nil {
			return nil, fmt.Errorf("json-nd encode: %w", err)
		}
	}
	return buf.Bytes(), nil
}

// ---------------------------------------------------------------------------
// CEF (ArcSight Common Event Format v0)
// Format: CEF:Version|DeviceVendor|DeviceProduct|DeviceVersion|SignatureID|Name|Severity|Extension
// ---------------------------------------------------------------------------

func exportCEF(events []domain.AuditEvent) ([]byte, error) {
	var buf bytes.Buffer
	for _, e := range events {
		// Build extension key=value pairs from metadata.
		ext := fmt.Sprintf("rt=%s suser=%s target=%s",
			e.Timestamp.UTC().Format(time.RFC3339),
			cefEscape(e.Actor),
			cefEscape(e.ResourceID),
		)
		for k, v := range e.Metadata {
			ext += fmt.Sprintf(" %s=%s", cefKey(k), cefEscape(fmt.Sprintf("%v", v)))
		}
		line := fmt.Sprintf("CEF:0|Authpilot|authpilot|1.0|%s|%s|5|%s\n",
			cefEscape(e.ID),
			cefEscape(e.EventType),
			ext,
		)
		buf.WriteString(line)
	}
	return buf.Bytes(), nil
}

// cefEscape replaces characters that CEF extension values must not contain.
func cefEscape(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	return s
}

// cefKey strips non-alphanumeric chars to produce a valid CEF extension key.
func cefKey(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Syslog RFC 5424
// <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
// ---------------------------------------------------------------------------

const (
	syslogFacility = 13 // log audit
	syslogSeverity = 6  // informational
	syslogPRI      = syslogFacility*8 + syslogSeverity
)

func exportSyslog(events []domain.AuditEvent) ([]byte, error) {
	var buf bytes.Buffer
	for _, e := range events {
		// Encode metadata as structured data [authpilot@0].
		sd := buildStructuredData(e)
		msg := fmt.Sprintf("<%d>1 %s authpilot - %s %s %s %s\n",
			syslogPRI,
			e.Timestamp.UTC().Format(time.RFC3339),
			e.EventType,
			e.ID,
			sd,
			syslogEscape(fmt.Sprintf("actor=%s resource=%s", e.Actor, e.ResourceID)),
		)
		buf.WriteString(msg)
	}
	return buf.Bytes(), nil
}

func buildStructuredData(e domain.AuditEvent) string {
	if len(e.Metadata) == 0 {
		return "-"
	}
	var parts []string
	for k, v := range e.Metadata {
		parts = append(parts, fmt.Sprintf(`%s="%s"`, sdParamName(k), sdEscape(fmt.Sprintf("%v", v))))
	}
	return fmt.Sprintf("[authpilot@0 %s]", strings.Join(parts, " "))
}

// sdParamName keeps only safe chars for SD-PARAM-NAME.
func sdParamName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r != '"' && r != '=' && r != ']' && r != ' ' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func sdEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, `]`, `\]`)
	return s
}

func syslogEscape(s string) string {
	return strings.ReplaceAll(s, "\n", " ")
}
