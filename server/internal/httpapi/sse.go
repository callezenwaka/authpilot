package httpapi

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

const (
	sseBufSize     = 16
	sseKeepalive   = 15 * time.Second
	sseRetryHintMS = 3000
)

// SSEBroadcaster fans SSE events out to all connected admin-SPA subscribers.
type SSEBroadcaster struct {
	mu   sync.Mutex
	subs map[chan string]struct{}
}

// NewSSEBroadcaster creates a ready-to-use broadcaster.
func NewSSEBroadcaster() *SSEBroadcaster {
	return &SSEBroadcaster{subs: make(map[chan string]struct{})}
}

func (b *SSEBroadcaster) subscribe() chan string {
	ch := make(chan string, sseBufSize)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	return ch
}

func (b *SSEBroadcaster) unsubscribe(ch chan string) {
	b.mu.Lock()
	delete(b.subs, ch)
	b.mu.Unlock()
	close(ch)
}

// Send broadcasts a named event to all subscribers. Non-blocking: slow consumers drop the event.
func (b *SSEBroadcaster) Send(eventType string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs {
		select {
		case ch <- eventType:
		default:
		}
	}
}

// sseHandler streams events to the admin SPA.
// Auth is enforced by the api subrouter middleware; the key may arrive as
// ?api_key= because EventSource cannot send custom request headers.
func sseHandler(b *SSEBroadcaster) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fl, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")

		fmt.Fprintf(w, "retry: %d\n\n", sseRetryHintMS)
		fl.Flush()

		ch := b.subscribe()
		defer b.unsubscribe(ch)

		ticker := time.NewTicker(sseKeepalive)
		defer ticker.Stop()

		for {
			select {
			case <-r.Context().Done():
				return
			case evt, ok := <-ch:
				if !ok {
					return
				}
				fmt.Fprintf(w, "event: %s\ndata: {}\n\n", evt)
				fl.Flush()
			case <-ticker.C:
				_, _ = fmt.Fprint(w, ": keepalive\n\n")
				fl.Flush()
			}
		}
	}
}
