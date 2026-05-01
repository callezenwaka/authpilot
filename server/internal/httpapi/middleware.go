package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"time"

	"furnace/server/internal/authevents"
	"furnace/server/internal/store"
	"furnace/server/internal/tenant"
)

type contextKey string

const (
	requestIDKey    contextKey = "request_id"
	apiKeyScopesKey contextKey = "api_key_scopes"
)

// GetAPIKeyScopes returns the scopes granted to the authenticated DB-issued API key,
// or nil when the request was authenticated with the static admin key.
func GetAPIKeyScopes(r *http.Request) []string {
	if v, ok := r.Context().Value(apiKeyScopesKey).([]string); ok {
		return v
	}
	return nil
}

// requestIDMiddleware generates a request ID for every incoming request and
// stores it on the context. The ID is also echoed back in X-Request-ID.
func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = newRequestID()
		}
		ctx := context.WithValue(r.Context(), requestIDKey, id)
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func getRequestID(r *http.Request) string {
	if id, ok := r.Context().Value(requestIDKey).(string); ok {
		return id
	}
	return ""
}

func newRequestID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "req_" + hex.EncodeToString(b)
}

// --- Rate limiting (token bucket per IP) ---

// RateLimiter is a per-IP token bucket rate limiter.
type RateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	limit    int           // max tokens
	refill   time.Duration // how often one token is added back
}

type bucket struct {
	tokens   int
	lastSeen time.Time
}

// NewRateLimiter creates a limiter allowing limit requests per window duration.
// e.g. NewRateLimiter(100, time.Minute) → 100 req/min per IP.
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		buckets: make(map[string]*bucket),
		limit:   limit,
		refill:  window / time.Duration(limit),
	}
	// Background goroutine evicts stale buckets every minute.
	go func() {
		ticker := time.NewTicker(time.Minute)
		for range ticker.C {
			rl.evict()
		}
	}()
	return rl
}

type allowResult struct {
	allowed   bool
	remaining int
	resetAt   time.Time // when the next token will be available
}

func (rl *RateLimiter) allow(ip string) bool {
	return rl.allowWithInfo(ip).allowed
}

func (rl *RateLimiter) allowWithInfo(ip string) allowResult {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, ok := rl.buckets[ip]
	if !ok {
		rl.buckets[ip] = &bucket{tokens: rl.limit - 1, lastSeen: now}
		return allowResult{allowed: true, remaining: rl.limit - 1, resetAt: now.Add(rl.refill)}
	}

	// Refill tokens based on elapsed time.
	elapsed := now.Sub(b.lastSeen)
	refilled := int(elapsed / rl.refill)
	if refilled > 0 {
		b.tokens += refilled
		if b.tokens > rl.limit {
			b.tokens = rl.limit
		}
		b.lastSeen = now
	}

	if b.tokens <= 0 {
		// Reset = when one full refill interval has elapsed since lastSeen.
		resetAt := b.lastSeen.Add(rl.refill)
		return allowResult{allowed: false, remaining: 0, resetAt: resetAt}
	}
	b.tokens--
	return allowResult{allowed: true, remaining: b.tokens, resetAt: now.Add(rl.refill)}
}

func (rl *RateLimiter) evict() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := time.Now().Add(-5 * time.Minute)
	for ip, b := range rl.buckets {
		if b.lastSeen.Before(cutoff) {
			delete(rl.buckets, ip)
		}
	}
}

// rateLimitMiddleware returns a middleware that enforces the given RateLimiter.
// X-Forwarded-For is honoured only when r.RemoteAddr is in one of trustedProxies;
// otherwise the function returns RemoteAddr's IP. Empty trustedProxies = XFF ignored.
// All responses include X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset.
// 429 responses additionally include Retry-After.
func rateLimitMiddleware(rl *RateLimiter, trustedProxies []*net.IPNet, sink authevents.Sink) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r, trustedProxies)
			res := rl.allowWithInfo(ip)
			resetUnix := res.resetAt.Unix()
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(rl.limit))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(res.remaining))
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetUnix, 10))
			if !res.allowed {
				sink.Emit(authevents.Event{
					Time: time.Now().UTC(),
					Type: authevents.TypeSignupAbuse,
					IP:   ip,
					Meta: map[string]any{"path": r.URL.Path, "limit": rl.limit},
				})
				retryAfter := res.resetAt.Unix() - time.Now().Unix()
				if retryAfter < 1 {
					retryAfter = 1
				}
				w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
				writeAPIError(w, r, http.StatusTooManyRequests, "RATE_LIMITED", "too many requests, slow down", true)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// clientIP returns the request's client IP. X-Forwarded-For is honoured only
// when r.RemoteAddr is inside one of the trustedProxies CIDRs — without that
// gate, any client can spoof the leftmost XFF value to bypass per-IP throttling.
// Empty trustedProxies = XFF ignored entirely.
func clientIP(r *http.Request, trustedProxies []*net.IPNet) string {
	remoteIP := remoteAddrIP(r.RemoteAddr)
	if len(trustedProxies) > 0 && remoteIP != "" && ipInCIDRs(remoteIP, trustedProxies) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if idx := strings.IndexByte(xff, ','); idx >= 0 {
				return strings.TrimSpace(xff[:idx])
			}
			return strings.TrimSpace(xff)
		}
	}
	return remoteIP
}

// remoteAddrIP strips the port suffix from r.RemoteAddr ("ip:port" or "[v6]:port").
func remoteAddrIP(remoteAddr string) string {
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return h
	}
	return remoteAddr
}

// ipInCIDRs reports whether ip falls inside any of the CIDRs.
func ipInCIDRs(ip string, cidrs []*net.IPNet) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, c := range cidrs {
		if c.Contains(parsed) {
			return true
		}
	}
	return false
}

// requestIsHTTPS reports whether the original client→edge connection used TLS.
// True when the Go server itself terminated TLS (r.TLS != nil) or when the
// request came from a trusted proxy that set X-Forwarded-Proto: https.
// X-Forwarded-Proto from an untrusted RemoteAddr is ignored — same trust model
// as clientIP. Used to set the Secure flag on cookies correctly behind LBs.
func requestIsHTTPS(r *http.Request, trustedProxies []*net.IPNet) bool {
	if r.TLS != nil {
		return true
	}
	if len(trustedProxies) == 0 {
		return false
	}
	remoteIP := remoteAddrIP(r.RemoteAddr)
	if remoteIP == "" || !ipInCIDRs(remoteIP, trustedProxies) {
		return false
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// --- Idempotency key caching ---

// idempotencyStore caches responses for POST requests that carry an Idempotency-Key.
type idempotencyStore struct {
	mu      sync.Mutex
	entries map[string]*idempotencyEntry
	ttl     time.Duration
}

type idempotencyEntry struct {
	status  int
	headers http.Header
	body    []byte
	created time.Time
}

// newIdempotencyStore creates a store with the given TTL for cached responses.
func newIdempotencyStore(ttl time.Duration) *idempotencyStore {
	s := &idempotencyStore{
		entries: make(map[string]*idempotencyEntry),
		ttl:     ttl,
	}
	go func() {
		ticker := time.NewTicker(time.Minute)
		for range ticker.C {
			s.evict()
		}
	}()
	return s
}

func (s *idempotencyStore) get(key string) (*idempotencyEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[key]
	if !ok || time.Since(e.created) > s.ttl {
		return nil, false
	}
	return e, true
}

func (s *idempotencyStore) set(key string, e *idempotencyEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[key] = e
}

func (s *idempotencyStore) evict() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, e := range s.entries {
		if time.Since(e.created) > s.ttl {
			delete(s.entries, k)
		}
	}
}

// idempotencyMiddleware intercepts POST requests with an Idempotency-Key header.
// On first request: execute normally, cache the response.
// On repeat request (same key within TTL): return cached response with Idempotent-Replayed: true.
func idempotencyMiddleware(store *idempotencyStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				next.ServeHTTP(w, r)
				return
			}
			key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
			if key == "" {
				next.ServeHTTP(w, r)
				return
			}

			cacheKey := r.Method + ":" + r.URL.Path + ":" + key

			// Return cached response if available.
			if entry, ok := store.get(cacheKey); ok {
				for k, vals := range entry.headers {
					for _, v := range vals {
						w.Header().Add(k, v)
					}
				}
				w.Header().Set("Idempotent-Replayed", "true")
				w.WriteHeader(entry.status)
				_, _ = w.Write(entry.body)
				return
			}

			// Capture the response.
			rec := httptest.NewRecorder()
			next.ServeHTTP(rec, r)

			entry := &idempotencyEntry{
				status:  rec.Code,
				headers: rec.Header().Clone(),
				body:    bytes.Clone(rec.Body.Bytes()),
				created: time.Now(),
			}
			store.set(cacheKey, entry)

			// Write the real response.
			for k, vals := range rec.Header() {
				for _, v := range vals {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(rec.Code)
			_, _ = w.Write(rec.Body.Bytes())
		})
	}
}

// extractAPIKey reads the API key from X-Furnace-Api-Key or Authorization: Bearer <key>.
func extractAPIKey(r *http.Request) string {
	if key := r.Header.Get("X-Furnace-Api-Key"); key != "" {
		return key
	}
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}

// apiKeyMiddleware protects /api/v1/* routes.
// Authentication succeeds when either:
//   - the incoming key matches the static apiKey, or
//   - keyStore is non-nil and the key's SHA-256 hash resolves to an active (non-revoked) DB key.
//
// Authenticated DB keys have their scopes injected into the request context
// (readable via GetAPIKeyScopes) and their last_used_at updated asynchronously.
func apiKeyMiddleware(apiKey string, keyStore store.APIKeyStore, sink authevents.Sink, trustedProxies []*net.IPNet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			incoming := extractAPIKey(r)

			// No auth configured — pass through (dev/test mode).
			if apiKey == "" && keyStore == nil {
				next.ServeHTTP(w, r)
				return
			}

			// Static key match — full access, no scope injection.
			if apiKey != "" && incoming == apiKey {
				next.ServeHTTP(w, r)
				return
			}

			// DB key lookup.
			if keyStore != nil && incoming != "" {
				hash := APIKeyHash(incoming)
				k, err := keyStore.GetByHash(hash)
				if err == nil && k.RevokedAt == nil {
					ctx := context.WithValue(r.Context(), apiKeyScopesKey, k.Scopes)
					go func() { _ = keyStore.UpdateLastUsed(k.ID, time.Now().UTC()) }()
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			sink.Emit(authevents.Event{
				Time: time.Now().UTC(),
				Type: authevents.TypeKeyRejected,
				IP:   clientIP(r, trustedProxies),
				Meta: map[string]any{"path": r.URL.Path},
			})
			writeAPIError(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "missing or invalid api key", false)
		})
	}
}

// TenantEntry maps an API key to a tenant ID. Used by tenantAPIKeyMiddleware.
type TenantEntry struct {
	TenantID string
	APIKey   string
	SCIMKey  string
}

// tenantAPIKeyMiddleware resolves the request's API key to a tenant ID and
// stores it on the context. Used only in multi-tenant mode.
func tenantAPIKeyMiddleware(tenants []TenantEntry, sink authevents.Sink, trustedProxies []*net.IPNet) func(http.Handler) http.Handler {
	// Build O(1) lookup maps.
	byAPIKey := make(map[string]TenantEntry, len(tenants))
	bySCIMKey := make(map[string]TenantEntry, len(tenants))
	for _, t := range tenants {
		byAPIKey[t.APIKey] = t
		if t.SCIMKey != "" {
			bySCIMKey[t.SCIMKey] = t
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := extractAPIKey(r)
			entry, ok := byAPIKey[key]
			if !ok {
				entry, ok = bySCIMKey[key]
			}
			if !ok {
				sink.Emit(authevents.Event{
					Time: time.Now().UTC(),
					Type: authevents.TypeKeyRejected,
					IP:   clientIP(r, trustedProxies),
					Meta: map[string]any{"path": r.URL.Path},
				})
				writeAPIError(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "missing or invalid api key", false)
				return
			}
			ctx := tenant.WithTenant(r.Context(), entry.TenantID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
