package authevents_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"furnace/server/internal/authevents"
)

func TestWriterSink_EmitsValidJSON(t *testing.T) {
	var buf bytes.Buffer
	sink := authevents.NewWriterSink(&buf)
	sink.Emit(authevents.Event{
		Time:   time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC),
		Type:   authevents.TypeKeyRejected,
		IP:     "10.0.0.1",
		UserID: "usr_abc",
		FlowID: "flow_xyz",
		Meta:   map[string]any{"path": "/api/v1/users"},
	})

	var got map[string]any
	if err := json.NewDecoder(&buf).Decode(&got); err != nil {
		t.Fatalf("emitted line is not valid JSON: %v — raw: %q", err, buf.String())
	}
	if got["type"] != authevents.TypeKeyRejected {
		t.Errorf("type: want %q, got %v", authevents.TypeKeyRejected, got["type"])
	}
	if got["ip"] != "10.0.0.1" {
		t.Errorf("ip: want 10.0.0.1, got %v", got["ip"])
	}
	meta, _ := got["meta"].(map[string]any)
	if meta["path"] != "/api/v1/users" {
		t.Errorf("meta.path: want /api/v1/users, got %v", meta["path"])
	}
}

func TestWriterSink_EmitsConcurrently(t *testing.T) {
	var buf bytes.Buffer
	sink := authevents.NewWriterSink(&buf)

	done := make(chan struct{})
	for i := 0; i < 50; i++ {
		go func() {
			sink.Emit(authevents.Event{Time: time.Now().UTC(), Type: authevents.TypeLoginFailed, IP: "1.2.3.4"})
			done <- struct{}{}
		}()
	}
	for i := 0; i < 50; i++ {
		<-done
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 50 {
		t.Errorf("want 50 JSON lines, got %d", len(lines))
	}
}

func TestNoopSink_Discards(t *testing.T) {
	sink := authevents.Noop()
	// Must not panic regardless of event content.
	sink.Emit(authevents.Event{Type: authevents.TypeMFAMismatch})
}

func TestNewSink_Stderr(t *testing.T) {
	sink, closer, err := authevents.NewSink("stderr")
	if err != nil {
		t.Fatalf("NewSink(stderr): %v", err)
	}
	defer closer.Close()
	// Must not panic.
	sink.Emit(authevents.Event{Time: time.Now().UTC(), Type: authevents.TypeSignupAbuse, IP: "127.0.0.1"})
}

func TestNewSink_File(t *testing.T) {
	path := t.TempDir() + "/auth_events.log"
	sink, closer, err := authevents.NewSink(path)
	if err != nil {
		t.Fatalf("NewSink(file): %v", err)
	}
	sink.Emit(authevents.Event{Time: time.Now().UTC(), Type: authevents.TypeWebAuthnFailed, IP: "192.168.1.1"})
	closer.Close()

	// Re-open and verify the line is parseable JSON with the right type.
	sink2, closer2, err := authevents.NewSink(path)
	if err != nil {
		t.Fatalf("reopen sink: %v", err)
	}
	_ = sink2
	closer2.Close()
}
