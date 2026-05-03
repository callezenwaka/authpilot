package httpapi

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"furnace/server/internal/store/memory"
)

// --- SSEBroadcaster unit tests ---

func TestSSEBroadcaster_SendReceive(t *testing.T) {
	b := NewSSEBroadcaster()
	ch := b.subscribe()
	defer b.unsubscribe(ch)

	b.Send("users")

	select {
	case evt := <-ch:
		if evt != "users" {
			t.Fatalf("expected %q, got %q", "users", evt)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestSSEBroadcaster_Unsubscribe(t *testing.T) {
	b := NewSSEBroadcaster()
	ch := b.subscribe()
	b.unsubscribe(ch)

	// Channel is closed after unsubscribe; a second unsubscribe must not panic.
	b.mu.Lock()
	_, still := b.subs[ch]
	b.mu.Unlock()
	if still {
		t.Fatal("channel still present after unsubscribe")
	}
}

func TestSSEBroadcaster_SlowConsumerDrops(t *testing.T) {
	b := NewSSEBroadcaster()
	ch := b.subscribe()
	defer b.unsubscribe(ch)

	// Fill the buffer completely.
	for i := 0; i < sseBufSize; i++ {
		b.Send("users")
	}
	// One more send must not block.
	done := make(chan struct{})
	go func() {
		b.Send("users")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Send blocked on full subscriber channel")
	}
}

func TestSSEBroadcaster_MultipleSubscribers(t *testing.T) {
	b := NewSSEBroadcaster()

	const n = 5
	chs := make([]chan string, n)
	for i := range chs {
		chs[i] = b.subscribe()
	}
	defer func() {
		for _, ch := range chs {
			b.unsubscribe(ch)
		}
	}()

	b.Send("groups")

	for i, ch := range chs {
		select {
		case evt := <-ch:
			if evt != "groups" {
				t.Fatalf("subscriber %d: expected %q, got %q", i, "groups", evt)
			}
		case <-time.After(time.Second):
			t.Fatalf("subscriber %d: timed out", i)
		}
	}
}

func TestSSEBroadcaster_ConcurrentSends(t *testing.T) {
	b := NewSSEBroadcaster()
	ch := b.subscribe()
	defer b.unsubscribe(ch)

	var wg sync.WaitGroup
	const goroutines = 20
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b.Send("flows")
		}()
	}
	wg.Wait()
	// No race or panic — test passes if we reach here.
}

// --- Integration tests for GET /api/v1/events ---

func TestSSEHandler_MissingKey_Returns401(t *testing.T) {
	router := NewRouter(Dependencies{
		Users:       memory.NewUserStore(),
		Groups:      memory.NewGroupStore(),
		Flows:       memory.NewFlowStore(),
		Sessions:    memory.NewSessionStore(),
		APIKey:      "test-key",
		Broadcaster: NewSSEBroadcaster(),
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestSSEHandler_ValidKey_StreamsEvents(t *testing.T) {
	bc := NewSSEBroadcaster()
	router := NewRouter(Dependencies{
		Users:       memory.NewUserStore(),
		Groups:      memory.NewGroupStore(),
		Flows:       memory.NewFlowStore(),
		Sessions:    memory.NewSessionStore(),
		APIKey:      "test-key",
		Broadcaster: bc,
	})

	// Use a real HTTP server so we get a real streaming connection.
	srv := httptest.NewServer(router)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/v1/events?api_key=test-key")
	if err != nil {
		t.Fatalf("GET /api/v1/events: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("expected text/event-stream, got %q", ct)
	}

	// Fire an event and read it from the stream.
	bc.Send("users")

	scanner := bufio.NewScanner(resp.Body)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !scanner.Scan() {
			break
		}
		line := scanner.Text()
		if line == "event: users" {
			return // success
		}
	}
	t.Fatal("did not receive 'event: users' line within deadline")
}

func TestSSEHandler_QueryParamKey(t *testing.T) {
	router := NewRouter(Dependencies{
		Users:       memory.NewUserStore(),
		Groups:      memory.NewGroupStore(),
		Flows:       memory.NewFlowStore(),
		Sessions:    memory.NewSessionStore(),
		APIKey:      "test-key",
		Broadcaster: NewSSEBroadcaster(),
	})

	srv := httptest.NewServer(router)
	defer srv.Close()

	// Key via query param (EventSource path).
	resp, err := http.Get(srv.URL + "/api/v1/events?api_key=test-key")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with ?api_key=, got %d", resp.StatusCode)
	}
}
