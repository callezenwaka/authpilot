// Package opa provides an embedded OPA evaluation engine for Furnace's
// /api/v1/opa/* endpoints. Policies are compiled and evaluated in-process
// using github.com/open-policy-agent/opa/v1/rego; no sidecar is required.
//
// Security limits:
//   - Compile and eval timeouts enforced via context.WithDeadline.
//   - Payload size limits enforced at the HTTP layer before OPA sees input.
//   - http.send, net.lookup_ip_addr, and opa.runtime built-ins are disabled.
//   - Batch concurrency is capped by a semaphore sized to runtime.NumCPU().
package opa

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	opav1 "github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/open-policy-agent/opa/v1/topdown"

	"furnace/server/internal/config"
)

// disabledBuiltins are removed from every evaluation context.
// Reason: http.send allows arbitrary outbound HTTP (data exfiltration),
// net.lookup_ip_addr performs DNS lookups (internal network probing), and
// opa.runtime exposes process env vars (credential leak in Docker/hosted).
var disabledBuiltins = []string{"http.send", "net.lookup_ip_addr", "opa.runtime"}

// Engine is a configured, reusable OPA evaluation engine.
type Engine struct {
	cfg       config.OPAConfig
	caps      *opav1.Capabilities
	sem       chan struct{} // batch concurrency semaphore
	decLog    *decisionLog
}

// NewEngine builds an Engine from cfg. MaxConcurrent defaults to
// runtime.NumCPU() when zero.
func NewEngine(cfg config.OPAConfig) (*Engine, error) {
	concurrency := cfg.MaxConcurrent
	if concurrency <= 0 {
		concurrency = runtime.NumCPU()
	}

	caps := opav1.CapabilitiesForThisVersion()
	caps.Builtins = slices.DeleteFunc(caps.Builtins, func(b *opav1.Builtin) bool {
		return slices.Contains(disabledBuiltins, b.Name)
	})

	dl, err := newDecisionLog(cfg.DecisionLog, cfg.TenantBudgets)
	if err != nil {
		return nil, fmt.Errorf("opa: init decision log: %w", err)
	}

	return &Engine{
		cfg:    cfg,
		caps:   caps,
		sem:    make(chan struct{}, concurrency),
		decLog: dl,
	}, nil
}

// DisabledBuiltins returns the list of built-in function names that are
// disabled in this engine. Exposed for the health endpoint.
func (e *Engine) DisabledBuiltins() []string { return disabledBuiltins }

// BudgetFor returns the resolved OPA resource limits for tenantID.
// Per-tenant values can only tighten global limits — the minimum of global
// and per-tenant is used for each field so a misconfigured override cannot
// loosen protection. When tenantID has no override, global values are returned.
func (e *Engine) BudgetFor(tenantID string) config.OPATenantBudget {
	budget := config.OPATenantBudget{
		EvalTimeout:    e.cfg.EvalTimeout,
		CompileTimeout: e.cfg.CompileTimeout,
		MaxPolicyBytes: e.cfg.MaxPolicyBytes,
		MaxDataBytes:   e.cfg.MaxDataBytes,
		MaxBatchChecks: e.cfg.MaxBatchChecks,
	}
	if e.cfg.TenantBudgets == nil {
		return budget
	}
	ov, ok := e.cfg.TenantBudgets[tenantID]
	if !ok {
		return budget
	}
	if ov.EvalTimeout > 0 && ov.EvalTimeout < budget.EvalTimeout {
		budget.EvalTimeout = ov.EvalTimeout
	}
	if ov.CompileTimeout > 0 && ov.CompileTimeout < budget.CompileTimeout {
		budget.CompileTimeout = ov.CompileTimeout
	}
	if ov.MaxPolicyBytes > 0 && ov.MaxPolicyBytes < budget.MaxPolicyBytes {
		budget.MaxPolicyBytes = ov.MaxPolicyBytes
	}
	if ov.MaxDataBytes > 0 && ov.MaxDataBytes < budget.MaxDataBytes {
		budget.MaxDataBytes = ov.MaxDataBytes
	}
	if ov.MaxBatchChecks > 0 && ov.MaxBatchChecks < budget.MaxBatchChecks {
		budget.MaxBatchChecks = ov.MaxBatchChecks
	}
	return budget
}

// EvalResult holds the outcome of a single Rego evaluation.
type EvalResult struct {
	Allow    bool
	Defined  bool           // false when no rule fired (eval_undefined)
	Bindings map[string]any // variable bindings from the query
	Trace    []TraceEvent
	EvalMS   int64
}

// EvalOptions parameterises one evaluation call.
type EvalOptions struct {
	PolicyText     string
	DataMap        map[string]any
	Input          map[string]any
	Query          string         // defaults to "data.authz.allow"
	WithTrace      bool
	CompileTimeout time.Duration  // 0 = use engine default
	EvalTimeout    time.Duration  // 0 = use engine default
}

// Eval compiles policyText and evaluates query against input+data.
// Returns EvalResult or a typed error (CompileError, EvalTimeoutError, etc.).
func (e *Engine) Eval(ctx context.Context, opts EvalOptions) (EvalResult, error) {
	query := opts.Query
	if query == "" {
		query = "data.authz.allow"
	}

	compileDL := e.cfg.CompileTimeout
	if opts.CompileTimeout > 0 && opts.CompileTimeout < compileDL {
		compileDL = opts.CompileTimeout
	}
	evalDL := e.cfg.EvalTimeout
	if opts.EvalTimeout > 0 && opts.EvalTimeout < evalDL {
		evalDL = opts.EvalTimeout
	}

	compileCtx, cancelCompile := context.WithTimeout(ctx, compileDL)
	defer cancelCompile()

	dataMap := opts.DataMap
	if dataMap == nil {
		dataMap = map[string]any{}
	}
	store := inmem.NewFromObject(dataMap)

	regoArgs := []func(*rego.Rego){
		rego.Query(query),
		rego.Module("policy.rego", opts.PolicyText),
		rego.Store(store),
		rego.Capabilities(e.caps),
	}

	var buf *topdown.BufferTracer
	if opts.WithTrace {
		buf = topdown.NewBufferTracer()
	}

	pq, err := rego.New(regoArgs...).PrepareForEval(compileCtx)
	if err != nil {
		if compileCtx.Err() != nil {
			opaCompileErrorsTotal.Inc()
			return EvalResult{}, &CompileTimeoutError{}
		}
		opaCompileErrorsTotal.Inc()
		return EvalResult{}, &CompileError{Message: err.Error()}
	}

	evalCtx, cancelEval := context.WithTimeout(ctx, evalDL)
	defer cancelEval()

	evalOpts := []rego.EvalOption{rego.EvalInput(opts.Input)}
	if buf != nil {
		evalOpts = append(evalOpts, rego.EvalQueryTracer(buf))
	}

	start := time.Now()
	rs, err := pq.Eval(evalCtx, evalOpts...)
	elapsed := time.Since(start)

	if err != nil {
		opaEvalTotal.WithLabelValues("error").Inc()
		opaEvalDuration.WithLabelValues("error").Observe(elapsed.Seconds())
		if evalCtx.Err() != nil {
			return EvalResult{}, &EvalTimeoutError{}
		}
		return EvalResult{}, fmt.Errorf("opa eval: %w", err)
	}

	result := EvalResult{EvalMS: elapsed.Milliseconds()}

	if opts.WithTrace && buf != nil {
		for _, ev := range *buf {
			result.Trace = append(result.Trace, TraceEvent{
				Op:   string(ev.Op),
				Node: fmt.Sprint(ev.Node),
			})
		}
	}

	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		result.Defined = false
		opaEvalTotal.WithLabelValues("undefined").Inc()
		opaEvalDuration.WithLabelValues("undefined").Observe(elapsed.Seconds())
		return result, nil
	}

	result.Defined = true
	expr := rs[0].Expressions[0].Value

	// If the query result is a structured object (decision document), extract allow.
	switch v := expr.(type) {
	case bool:
		result.Allow = v
	case map[string]any:
		result.Bindings = v
		if a, ok := v["allow"].(bool); ok {
			result.Allow = a
		}
	}

	decision := "deny"
	if result.Allow {
		decision = "grant"
	}
	opaEvalTotal.WithLabelValues(decision).Inc()
	opaEvalDuration.WithLabelValues(decision).Observe(elapsed.Seconds())

	return result, nil
}

// AcquireSemaphore blocks until a batch slot is available.
func (e *Engine) AcquireSemaphore(ctx context.Context) error {
	select {
	case e.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ReleaseSemaphore returns a batch slot.
func (e *Engine) ReleaseSemaphore() { <-e.sem }

// LogDecision writes one entry to the decision log if enabled.
func (e *Engine) LogDecision(entry DecisionEntry) {
	e.decLog.write(entry)
}

// DecisionEntry is one record in the OPA decision log.
type DecisionEntry struct {
	Timestamp     time.Time      `json:"timestamp"`
	RequestID     string         `json:"request_id,omitempty"`
	TenantID      string         `json:"tenant_id,omitempty"`
	UserID        string         `json:"user_id,omitempty"`
	Action        string         `json:"action,omitempty"`
	Resource      string         `json:"resource,omitempty"`
	Allow         bool           `json:"allow"`
	Decision      string         `json:"decision"`
	PolicyVersion string         `json:"policy_version"`
	ContentHash   string         `json:"content_hash,omitempty"` // SHA-256 of policy content; populated for stored policies
	EvalMS        int64          `json:"eval_ms"`
	Input         map[string]any `json:"input,omitempty"`
	Policy        string         `json:"policy,omitempty"`
	// TenantOverrides carries per-tenant decision log settings resolved from
	// OPATenantBudget.DecisionLog. It is applied at write time and is never
	// serialised into the log entry (json:"-").
	TenantOverrides *config.OPATenantDecisionLog `json:"-"`
}

// ---- typed errors ----

// CompileError is returned when Rego fails to compile.
type CompileError struct{ Message string }

func (e *CompileError) Error() string { return "compile error: " + e.Message }

// CompileTimeoutError is returned when compilation exceeds its deadline.
type CompileTimeoutError struct{}

func (e *CompileTimeoutError) Error() string { return "compile timeout" }

// EvalTimeoutError is returned when evaluation exceeds its deadline.
type EvalTimeoutError struct{}

func (e *EvalTimeoutError) Error() string { return "eval timeout" }

// ---- decision log ----

// credentialPatterns are compiled once and used to scrub credential-like strings
// from policy text before it is written to the decision log.
var credentialPatterns = []*regexp.Regexp{
	// Bearer / token values: Bearer <long-value>
	regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._\-]{20,}`),
	// Assignment of credential keywords to quoted values: password = "secret"
	regexp.MustCompile(`(?i)((?:password|secret|token|api_?key|auth)\s*[:=]\s*["'])[^"']{4,}(["'])`),
	// Long bare base64 strings (40+ chars) that aren't doc comments
	regexp.MustCompile(`(?:^|[\s=:])([A-Za-z0-9+/]{40,}={0,2})(?:$|[\s,;])`),
}

type decisionLog struct {
	cfg           config.OPADecisionLogConfig
	tenantBudgets map[string]config.OPATenantBudget
	mu            sync.Mutex
	w             interface{ Write([]byte) (int, error) }
	enc           *json.Encoder
	file          *os.File // non-nil when writing to a file path
}

func newDecisionLog(cfg config.OPADecisionLogConfig, tenantBudgets map[string]config.OPATenantBudget) (*decisionLog, error) {
	if !cfg.Enabled {
		return &decisionLog{cfg: cfg, tenantBudgets: tenantBudgets}, nil
	}
	dl := &decisionLog{cfg: cfg, tenantBudgets: tenantBudgets}
	switch cfg.Destination {
	case "", "stdout":
		dl.w = writerFunc(func(p []byte) (int, error) {
			fmt.Print(string(p))
			return len(p), nil
		})
	case "stderr":
		dl.w = writerFunc(func(p []byte) (int, error) {
			fmt.Fprint(os.Stderr, string(p))
			return len(p), nil
		})
	default:
		// File path — apply retention pruning on open (global + per-tenant), then append.
		if err := pruneDecisionLog(cfg.Destination, cfg.RetentionDays, tenantBudgets); err != nil {
			// Non-fatal: log to stderr and continue.
			fmt.Fprintf(os.Stderr, "opa: decision log retention prune: %v\n", err)
		}
		f, err := os.OpenFile(cfg.Destination, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, fmt.Errorf("open decision log %q: %w", cfg.Destination, err)
		}
		dl.file = f
		dl.w = f
	}
	dl.enc = json.NewEncoder(dl.w)
	return dl, nil
}

// Close releases the underlying file handle when writing to a file path.
func (d *decisionLog) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.file != nil {
		return d.file.Close()
	}
	return nil
}

func (d *decisionLog) write(entry DecisionEntry) {
	if !d.cfg.Enabled || d.enc == nil {
		return
	}

	// Build effective redact list and scrub flag, merging per-tenant additions.
	redactFields := d.cfg.RedactFields
	doScrub := d.cfg.ScrubPolicyCredentials
	if entry.TenantOverrides != nil {
		if len(entry.TenantOverrides.AdditionalRedactFields) > 0 {
			merged := make([]string, 0, len(redactFields)+len(entry.TenantOverrides.AdditionalRedactFields))
			merged = append(merged, redactFields...)
			merged = append(merged, entry.TenantOverrides.AdditionalRedactFields...)
			redactFields = merged
		}
		if entry.TenantOverrides.ScrubPolicyCredentials {
			doScrub = true
		}
	}

	if !d.cfg.IncludeInput {
		entry.Input = nil
	} else if len(redactFields) > 0 && entry.Input != nil {
		entry.Input = deepCloneMap(entry.Input)
		for _, path := range redactFields {
			redactPath(entry.Input, path)
		}
	}
	if !d.cfg.IncludePolicy {
		entry.Policy = ""
	} else if doScrub && entry.Policy != "" {
		entry.Policy = scrubCredentials(entry.Policy)
	}
	d.mu.Lock()
	_ = d.enc.Encode(entry)
	d.mu.Unlock()
}

// redactPath sets the value at the dot-separated path in m to "[REDACTED]".
// Missing intermediate keys are silently ignored.
func redactPath(m map[string]any, path string) {
	idx := strings.IndexByte(path, '.')
	if idx < 0 {
		// Leaf.
		if _, ok := m[path]; ok {
			m[path] = "[REDACTED]"
		}
		return
	}
	key, rest := path[:idx], path[idx+1:]
	if nested, ok := m[key].(map[string]any); ok {
		redactPath(nested, rest)
	}
}

// deepCloneMap returns a shallow-at-each-level clone of m sufficient to let
// redactPath mutate leaf values without corrupting the caller's map.
func deepCloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		if nested, ok := v.(map[string]any); ok {
			out[k] = deepCloneMap(nested)
		} else {
			out[k] = v
		}
	}
	return out
}

// scrubCredentials replaces credential-like patterns in policy text with
// placeholder tokens before the text is written to the decision log.
func scrubCredentials(policy string) string {
	out := policy
	out = credentialPatterns[0].ReplaceAllString(out, "${1}[REDACTED]")
	out = credentialPatterns[1].ReplaceAllString(out, "${1}[REDACTED]${2}")
	out = credentialPatterns[2].ReplaceAllStringFunc(out, func(s string) string {
		// Preserve surrounding whitespace; replace only the base64 blob.
		return credentialPatterns[2].ReplaceAllString(s, "[REDACTED_BASE64]")
	})
	return out
}

// pruneDecisionLog rewrites path in place, keeping only NDJSON lines whose
// "timestamp" field is within the effective retention window. The effective
// retention for each line is min(globalRetentionDays, per-tenant override) when
// a tenant-specific RetentionDays is configured and tighter; otherwise the
// global value is used. Lines that cannot be parsed are kept (conservative).
// No-op when the file does not exist or no retention is configured anywhere.
func pruneDecisionLog(path string, globalRetentionDays int, tenantBudgets map[string]config.OPATenantBudget) error {
	if globalRetentionDays <= 0 && !hasAnyTenantRetention(tenantBudgets) {
		return nil
	}

	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	var kept [][]byte
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec struct {
			Timestamp time.Time `json:"timestamp"`
			TenantID  string    `json:"tenant_id"`
		}
		if err := json.Unmarshal(line, &rec); err != nil || rec.Timestamp.IsZero() {
			kept = append(kept, append([]byte(nil), line...)) // keep unparseable lines
			continue
		}

		// Determine effective retention: tighter of global and per-tenant.
		effective := globalRetentionDays
		if rec.TenantID != "" && tenantBudgets != nil {
			if tb, ok := tenantBudgets[rec.TenantID]; ok && tb.DecisionLog != nil && tb.DecisionLog.RetentionDays > 0 {
				if effective == 0 || tb.DecisionLog.RetentionDays < effective {
					effective = tb.DecisionLog.RetentionDays
				}
			}
		}

		if effective <= 0 || rec.Timestamp.UTC().After(now.AddDate(0, 0, -effective)) {
			kept = append(kept, append([]byte(nil), line...))
		}
	}
	f.Close()
	if err := sc.Err(); err != nil {
		return fmt.Errorf("scan decision log: %w", err)
	}

	// Rewrite atomically via a temp file.
	tmp := path + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open temp file: %w", err)
	}
	for _, line := range kept {
		out.Write(line)  //nolint:errcheck
		out.Write([]byte{'\n'}) //nolint:errcheck
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp) //nolint:errcheck
		return err
	}
	return os.Rename(tmp, path)
}

// hasAnyTenantRetention reports whether any tenant in budgets has a per-tenant
// RetentionDays configured so pruneDecisionLog can skip scanning when nothing
// would be pruned.
func hasAnyTenantRetention(budgets map[string]config.OPATenantBudget) bool {
	for _, b := range budgets {
		if b.DecisionLog != nil && b.DecisionLog.RetentionDays > 0 {
			return true
		}
	}
	return false
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// BuildInput constructs the OPA input document from a raw input map,
// injecting action/resource/context at the top level when provided.
func BuildInput(raw map[string]any, action, resource string, ctx map[string]any) map[string]any {
	in := make(map[string]any, len(raw)+3)
	for k, v := range raw {
		in[k] = v
	}
	if action != "" {
		in["action"] = action
	}
	if resource != "" {
		in["resource"] = resource
	}
	if len(ctx) > 0 {
		in["context"] = ctx
	}
	return in
}

// ParseJWTClaims extracts the payload claims from a compact JWT without
// verifying the signature. Used by the token-pipeline endpoint which
// receives tokens that may be from external providers.
func ParseJWTClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a compact JWT")
	}
	payload, err := decodeBase64URL(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal claims: %w", err)
	}
	return claims, nil
}

func decodeBase64URL(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
