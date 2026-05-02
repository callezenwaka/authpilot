package opa

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	opaversion "github.com/open-policy-agent/opa/v1/version"

	"furnace/server/internal/config"
	"furnace/server/internal/domain"
	"furnace/server/internal/personality"
	"furnace/server/internal/store"
	"furnace/server/internal/tenant"
)

// RouterDeps groups everything the OPA router needs.
type RouterDeps struct {
	Engine   *Engine
	Users    store.UserStore
	Policies store.PolicyStore
}

// NewRouter mounts all /api/v1/opa/* routes.
// publicRouter receives the health endpoints (no auth required).
// authedAPI is the /api/v1 subrouter that already has API key middleware applied.
func NewRouter(dep RouterDeps, publicRouter *mux.Router, authedAPI *mux.Router) {
	publicRouter.HandleFunc("/api/v1/opa/health", healthHandler(dep)).Methods(http.MethodGet)
	publicRouter.HandleFunc("/api/v1/opa/health/ready", readyHandler(dep)).Methods(http.MethodGet)

	authedAPI.HandleFunc("/opa/evaluate", evaluateHandler(dep)).Methods(http.MethodPost)
	authedAPI.HandleFunc("/opa/evaluate/batch", batchHandler(dep)).Methods(http.MethodPost)
	authedAPI.HandleFunc("/opa/evaluate/token-pipeline", tokenPipelineHandler(dep)).Methods(http.MethodPost)
	authedAPI.HandleFunc("/opa/validate", validateHandler(dep)).Methods(http.MethodPost)
	authedAPI.HandleFunc("/opa/diff", diffHandler(dep)).Methods(http.MethodPost)

	// Policy Admin — only mounted when a policy store is wired up.
	if dep.Policies != nil {
		authedAPI.HandleFunc("/opa/policies", listPoliciesHandler(dep)).Methods(http.MethodGet)
		authedAPI.HandleFunc("/opa/policies", createPolicyHandler(dep)).Methods(http.MethodPost)
		authedAPI.HandleFunc("/opa/policies/{id}", getPolicyHandler(dep)).Methods(http.MethodGet)
		authedAPI.HandleFunc("/opa/policies/{id}", deletePolicyHandler(dep)).Methods(http.MethodDelete)
		authedAPI.HandleFunc("/opa/policies/{id}/activate", activatePolicyHandler(dep)).Methods(http.MethodPost)
	}
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

func healthHandler(dep RouterDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, HealthResponse{
			Status:           "ok",
			Engine:           "embedded",
			OPAVersion:       opaversion.Version,
			EvaluationTest:   "passed",
			DisabledBuiltins: dep.Engine.DisabledBuiltins(),
		})
	}
}

func readyHandler(dep RouterDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Run a minimal test evaluation to confirm the engine is warm.
		_, err := dep.Engine.Eval(r.Context(), EvalOptions{
			PolicyText: `package authz
default allow := false
allow if { input.ready == true }`,
			DataMap: map[string]any{},
			Input:   map[string]any{"ready": true},
			Query:   "data.authz.allow",
		})
		if err != nil {
			writeOPAError(w, http.StatusServiceUnavailable, "engine_error", "readiness check failed: "+err.Error(), nil)
			return
		}
		writeJSON(w, http.StatusOK, HealthResponse{
			Status:           "ok",
			Engine:           "embedded",
			OPAVersion:       opaversion.Version,
			EvaluationTest:   "passed",
			DisabledBuiltins: dep.Engine.DisabledBuiltins(),
		})
	}
}

// ---------------------------------------------------------------------------
// Evaluate — single check
// ---------------------------------------------------------------------------

func evaluateHandler(dep RouterDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req EvaluateRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		if err := validateEvaluateReq(req); err != nil {
			writeOPAError(w, http.StatusBadRequest, "validation_error", err.Error(), nil)
			return
		}

		policyVersion := "inline"
		var policyContentHash string

		if req.Policy == "" {
			if dep.Policies == nil {
				writeOPAError(w, http.StatusBadRequest, "validation_error", "policy store not configured; supply 'policy' field", nil)
				return
			}
			p, err := dep.Policies.GetByName(req.PolicyName)
			if err != nil {
				if errors.Is(err, store.ErrPolicyTampered) {
					writeOPAError(w, http.StatusUnprocessableEntity, "policy_tampered",
						fmt.Sprintf("active policy %q failed integrity check; re-activate to re-sign", req.PolicyName), nil)
					return
				}
				if errors.Is(err, store.ErrNotFound) {
					writeOPAError(w, http.StatusNotFound, "not_found", fmt.Sprintf("no active policy named %q", req.PolicyName), nil)
					return
				}
				writeOPAError(w, http.StatusInternalServerError, "server_error", err.Error(), nil)
				return
			}
			req.Policy = p.Content
			policyVersion = p.Name + "@" + p.Version
			policyContentHash = p.ContentHash
		}

		// provider=="all" runs every personality and returns a comparison.
		if req.Provider == "all" {
			handleMultiProvider(w, r, dep, req)
			return
		}

		budget := dep.Engine.BudgetFor(tenant.FromContext(r.Context()))

		if int64(len(req.Policy)) > budget.MaxPolicyBytes {
			writeOPAError(w, http.StatusRequestEntityTooLarge, "payload_too_large",
				fmt.Sprintf("policy exceeds limit of %d bytes", budget.MaxPolicyBytes), nil)
			return
		}
		if len(req.Data) > 0 {
			if dataBytes, err := json.Marshal(req.Data); err == nil && int64(len(dataBytes)) > budget.MaxDataBytes {
				writeOPAError(w, http.StatusRequestEntityTooLarge, "payload_too_large",
					fmt.Sprintf("data exceeds limit of %d bytes", budget.MaxDataBytes), nil)
				return
			}
		}

		input, err := buildInputForRequest(dep, req)
		if err != nil {
			writeOPAError(w, http.StatusBadRequest, "validation_error", err.Error(), nil)
			return
		}

		query := req.Query
		if query == "" {
			query = "data.authz.allow"
		}

		opts := EvalOptions{
			PolicyText: req.Policy,
			DataMap:    req.Data,
			Input:      input,
			Query:      query,
			WithTrace:  req.Trace,
		}
		applyTimeoutOverride(&opts, req.Timeouts, budget)

		result, err := dep.Engine.Eval(r.Context(), opts)
		if err != nil {
			writeEvalError(w, err)
			return
		}

		resp := buildEvaluateResponse(result, query, input, req.Trace)
		resp.PolicyVersion = policyVersion
		dep.Engine.LogDecision(DecisionEntry{
			Timestamp:       resp.EvaluationTimestamp,
			TenantID:        tenant.FromContext(r.Context()),
			UserID:          req.UserID,
			Action:          req.Action,
			Resource:        req.Resource,
			Allow:           resp.Allow,
			Decision:        resp.Decision,
			PolicyVersion:   policyVersion,
			ContentHash:     policyContentHash,
			EvalMS:          result.EvalMS,
			Input:           input,
			Policy:          req.Policy,
			TenantOverrides: budget.DecisionLog,
		})
		writeJSON(w, http.StatusOK, resp)
	}
}

func handleMultiProvider(w http.ResponseWriter, r *http.Request, dep RouterDeps, req EvaluateRequest) {
	user, err := resolveUser(dep, req.UserID)
	if err != nil {
		writeOPAError(w, http.StatusBadRequest, "validation_error", "user_id: "+err.Error(), nil)
		return
	}

	query := req.Query
	if query == "" {
		query = "data.authz.allow"
	}

	personalities := personality.All()
	resultsByProvider := make(map[string]ProviderResult, len(personalities))
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, p := range personalities {
		wg.Add(1)
		go func(p *personality.Personality) {
			defer wg.Done()
			baseClaims := userToClaims(user)
			shaped := p.Apply(baseClaims)
			input := BuildInput(map[string]any{"user": shaped}, req.Action, req.Resource, req.Context)

			res, err := dep.Engine.Eval(r.Context(), EvalOptions{
				PolicyText: req.Policy,
				DataMap:    req.Data,
				Input:      input,
				Query:      query,
			})
			pr := ProviderResult{}
			if err != nil {
				pr.Decision = "error"
				pr.Error = err.Error()
			} else if !res.Defined {
				pr.Decision = "undefined"
			} else if res.Allow {
				pr.Allow = true
				pr.Decision = "grant"
			} else {
				pr.Decision = "deny"
			}
			mu.Lock()
			resultsByProvider[p.ID] = pr
			mu.Unlock()
		}(p)
	}
	wg.Wait()

	var passing, failing []string
	for name, pr := range resultsByProvider {
		if pr.Allow {
			passing = append(passing, name)
		} else {
			failing = append(failing, name)
		}
	}
	sort.Strings(passing)
	sort.Strings(failing)

	writeJSON(w, http.StatusOK, MultiProviderEvaluateResponse{
		ResultsByProvider:   resultsByProvider,
		ProvidersPass:       passing,
		ProvidersFail:       failing,
		EvaluationTimestamp: time.Now().UTC(),
	})
}

// ---------------------------------------------------------------------------
// Batch
// ---------------------------------------------------------------------------

func batchHandler(dep RouterDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req BatchRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		if req.Policy == "" {
			writeOPAError(w, http.StatusBadRequest, "validation_error", "supply 'policy' field", nil)
			return
		}
		if len(req.Checks) == 0 {
			writeOPAError(w, http.StatusBadRequest, "validation_error", "'checks' must be non-empty", nil)
			return
		}
		budget := dep.Engine.BudgetFor(tenant.FromContext(r.Context()))

		if int64(len(req.Policy)) > budget.MaxPolicyBytes {
			writeOPAError(w, http.StatusRequestEntityTooLarge, "payload_too_large",
				fmt.Sprintf("policy exceeds limit of %d bytes", budget.MaxPolicyBytes), nil)
			return
		}
		if len(req.Checks) > budget.MaxBatchChecks {
			writeOPAError(w, http.StatusRequestEntityTooLarge, "payload_too_large",
				fmt.Sprintf("checks exceeds maximum of %d", budget.MaxBatchChecks), nil)
			return
		}

		baseInput, err := buildBatchBaseInput(dep, req)
		if err != nil {
			writeOPAError(w, http.StatusBadRequest, "validation_error", err.Error(), nil)
			return
		}

		query := req.Query
		if query == "" {
			query = "data.authz.allow"
		}

		opaBatchSize.Observe(float64(len(req.Checks)))

		results := make([]BatchResult, len(req.Checks))
		var wg sync.WaitGroup
		for i, check := range req.Checks {
			wg.Add(1)
			go func(idx int, c BatchCheck) {
				defer wg.Done()
				if err := dep.Engine.AcquireSemaphore(r.Context()); err != nil {
					results[idx] = BatchResult{Action: c.Action, Resource: c.Resource, Decision: "error", Error: "semaphore: " + err.Error()}
					return
				}
				defer dep.Engine.ReleaseSemaphore()

				input := maps.Clone(baseInput)
				input["action"] = c.Action
				input["resource"] = c.Resource

				opts := EvalOptions{
					PolicyText: req.Policy,
					DataMap:    req.Data,
					Input:      input,
					Query:      query,
				}
				applyTimeoutOverride(&opts, req.Timeouts, budget)

				res, err := dep.Engine.Eval(r.Context(), opts)
				if err != nil {
					results[idx] = BatchResult{Action: c.Action, Resource: c.Resource, Decision: "error", Error: err.Error()}
					return
				}
				decision := "deny"
				if !res.Defined {
					decision = "undefined"
				} else if res.Allow {
					decision = "grant"
				}
				results[idx] = BatchResult{Action: c.Action, Resource: c.Resource, Allow: res.Allow, Decision: decision}
			}(i, check)
		}
		wg.Wait()

		grant, deny := 0, 0
		for _, res := range results {
			if res.Allow {
				grant++
			} else {
				deny++
			}
		}

		writeJSON(w, http.StatusOK, BatchResponse{
			UserID:              req.UserID,
			Context:             req.Context,
			TotalChecks:         len(req.Checks),
			Grant:               grant,
			Deny:                deny,
			Results:             results,
			EvaluationTimestamp: time.Now().UTC(),
		})
	}
}

// ---------------------------------------------------------------------------
// Validate
// ---------------------------------------------------------------------------

func validateHandler(_ RouterDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req ValidateRequest
		if !decodeJSON(w, r, &req) {
			return
		}

		var errs, warnings []string

		// Universal checks — apply regardless of schema.
		if perms, ok := req.Data["permissions"].(map[string]any); ok {
			for resource, roleMap := range perms {
				rm, ok := roleMap.(map[string]any)
				if !ok {
					continue
				}
				for _, actions := range rm {
					switch av := actions.(type) {
					case map[string]any:
						for action, state := range av {
							s, ok := state.(string)
							if !ok {
								continue
							}
							if s != "allow" && s != "deny" && s != "conditional" {
								errs = append(errs, fmt.Sprintf("permissions.%s: invalid state %q for action %q (must be allow|deny|conditional)", resource, s, action))
							}
						}
					}
				}
			}
		}

		// Tristate-specific checks.
		if req.Schema == "tristate" {
			roles, hasRoles := req.Data["roles"].(map[string]any)
			perms, hasPerms := req.Data["permissions"].(map[string]any)

			if hasRoles && hasPerms {
				for resource, roleMap := range perms {
					rm, ok := roleMap.(map[string]any)
					if !ok {
						continue
					}
					for role := range rm {
						if _, defined := roles[role]; !defined {
							errs = append(errs, fmt.Sprintf("permissions.%s: role %q not defined in roles", resource, role))
						}
					}
				}
				for role, roleData := range roles {
					rd, ok := roleData.(map[string]any)
					if !ok {
						continue
					}
					if _, hasLevel := rd["level"]; !hasLevel {
						errs = append(errs, fmt.Sprintf("roles.%s: missing required 'level' field", role))
					}
				}
			}

			if hasPerms {
				systems, hasSystems := req.Data["systems"].(map[string]any)
				if hasSystems {
					for resource := range perms {
						top := strings.SplitN(resource, ".", 2)[0]
						if _, ok := systems[top]; !ok {
							warnings = append(warnings, fmt.Sprintf("permissions resource %q has no matching entry in systems", resource))
						}
					}
				}
			}
		}

		sort.Strings(errs)
		sort.Strings(warnings)
		writeJSON(w, http.StatusOK, ValidateResponse{
			Valid:    len(errs) == 0,
			Errors:   errs,
			Warnings: warnings,
		})
	}
}

// ---------------------------------------------------------------------------
// Diff
// ---------------------------------------------------------------------------

func diffHandler(_ RouterDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req DiffRequest
		if !decodeJSON(w, r, &req) {
			return
		}

		resp := computeDiff(req.Before, req.After)
		writeJSON(w, http.StatusOK, resp)
	}
}

func computeDiff(before, after map[string]any) DiffResponse {
	resp := DiffResponse{
		AddedRoles:         []string{},
		RemovedRoles:       []string{},
		AddedSystems:       []string{},
		RemovedSystems:     []string{},
		AddedPermissions:   []string{},
		RemovedPermissions: []string{},
		ChangedPermissions: []PermChange{},
	}

	beforeRoles := stringKeys(mapField(before, "roles"))
	afterRoles := stringKeys(mapField(after, "roles"))
	resp.AddedRoles, resp.RemovedRoles = setDiff(afterRoles, beforeRoles)

	beforePerms := mapField(before, "permissions")
	afterPerms := mapField(after, "permissions")
	allResources := unionKeys(beforePerms, afterPerms)

	bumpLevel := "none"
	if len(resp.AddedRoles) > 0 || len(resp.RemovedRoles) > 0 {
		bumpLevel = "major"
	}

	var summaryParts []string
	for _, resource := range allResources {
		bv, inBefore := beforePerms[resource]
		av, inAfter := afterPerms[resource]
		if !inBefore {
			resp.AddedPermissions = append(resp.AddedPermissions, resource)
			bumpLevel = bumpMax(bumpLevel, "minor")
			continue
		}
		if !inAfter {
			resp.RemovedPermissions = append(resp.RemovedPermissions, resource)
			bumpLevel = bumpMax(bumpLevel, "minor")
			continue
		}
		beforeRM, _ := bv.(map[string]any)
		afterRM, _ := av.(map[string]any)
		change := PermChange{Resource: resource, Changes: map[string]RolePermChanges{}}
		for _, role := range unionKeys(beforeRM, afterRM) {
			bRole, _ := beforeRM[role].(map[string]any)
			aRole, _ := afterRM[role].(map[string]any)
			old, nw := map[string]any{}, map[string]any{}
			for _, action := range unionKeys(bRole, aRole) {
				bv2, bOk := bRole[action]
				av2, aOk := aRole[action]
				if bOk && aOk && fmt.Sprint(bv2) != fmt.Sprint(av2) {
					old[action] = bv2
					nw[action] = av2
				}
			}
			if len(old) > 0 {
				change.Changes[role] = RolePermChanges{Old: old, New: nw}
			}
		}
		if len(change.Changes) > 0 {
			resp.ChangedPermissions = append(resp.ChangedPermissions, change)
			summaryParts = append(summaryParts, resource)
			bumpLevel = bumpMax(bumpLevel, "patch")
		}
	}

	resp.RecommendedBump = bumpLevel
	if len(summaryParts) > 0 {
		resp.Summary = "Changed permissions for: " + strings.Join(summaryParts, ", ")
	}
	return resp
}

// ---------------------------------------------------------------------------
// Token pipeline
// ---------------------------------------------------------------------------

func tokenPipelineHandler(dep RouterDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req TokenPipelineRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		if req.Policy == "" {
			writeOPAError(w, http.StatusBadRequest, "validation_error", "supply 'policy' field", nil)
			return
		}
		if req.FurnaceToken == "" && req.ProviderToken == "" {
			writeOPAError(w, http.StatusBadRequest, "validation_error", "supply at least one of 'furnace_token' or 'provider_token'", nil)
			return
		}

		budget := dep.Engine.BudgetFor(tenant.FromContext(r.Context()))

		if int64(len(req.Policy)) > budget.MaxPolicyBytes {
			writeOPAError(w, http.StatusRequestEntityTooLarge, "payload_too_large",
				fmt.Sprintf("policy exceeds limit of %d bytes", budget.MaxPolicyBytes), nil)
			return
		}

		query := req.Query
		if query == "" {
			query = "data.authz.allow"
		}

		resp := TokenPipelineResponse{
			Query:               query,
			EvaluationTimestamp: time.Now().UTC(),
		}

		evalToken := func(tokenStr, label string) (*TokenPipelineResult, []ClaimDiff) {
			claims, err := ParseJWTClaims(tokenStr)
			if err != nil {
				return &TokenPipelineResult{Decision: "error", Error: "invalid JWT: " + err.Error()}, nil
			}
			input := BuildInput(map[string]any{"user": map[string]any{"claims": claims}}, req.Action, req.Resource, req.Context)
			opts := EvalOptions{
				PolicyText: req.Policy,
				DataMap:    req.Data,
				Input:      input,
				Query:      query,
			}
			applyTimeoutOverride(&opts, req.Timeouts, budget)
			res, evalErr := dep.Engine.Eval(r.Context(), opts)
			if evalErr != nil {
				d := "error"
				return &TokenPipelineResult{Decision: d, Error: evalErr.Error()}, nil
			}
			decision := "deny"
			if !res.Defined {
				decision = "undefined"
			} else if res.Allow {
				decision = "grant"
			}
			return &TokenPipelineResult{Allow: res.Allow, Decision: decision, ClaimsUsed: claims}, nil
		}

		var furnaceClaims, providerClaims map[string]any
		if req.FurnaceToken != "" {
			result, _ := evalToken(req.FurnaceToken, "furnace")
			resp.FurnaceResult = result
			furnaceClaims = result.ClaimsUsed
		}
		if req.ProviderToken != "" {
			result, _ := evalToken(req.ProviderToken, "provider")
			resp.ProviderResult = result
			providerClaims = result.ClaimsUsed
		}

		if resp.FurnaceResult != nil && resp.ProviderResult != nil {
			resp.DecisionMatches = resp.FurnaceResult.Allow == resp.ProviderResult.Allow
			resp.ClaimDifferences = diffClaims(furnaceClaims, providerClaims)
		}

		writeJSON(w, http.StatusOK, resp)
	}
}

// ---------------------------------------------------------------------------
// Policy Admin
// ---------------------------------------------------------------------------

func listPoliciesHandler(dep RouterDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		policies, err := dep.Policies.List()
		if err != nil {
			writeOPAError(w, http.StatusInternalServerError, "server_error", err.Error(), nil)
			return
		}
		items := make([]PolicyResponse, len(policies))
		for i, p := range policies {
			items[i] = policyToResponse(p)
		}
		writeJSON(w, http.StatusOK, PolicyListResponse{Policies: items, Total: len(items)})
	}
}

func createPolicyHandler(dep RouterDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req PolicyCreateRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		if req.Name == "" {
			writeOPAError(w, http.StatusBadRequest, "validation_error", "'name' is required", nil)
			return
		}
		if req.Version == "" {
			writeOPAError(w, http.StatusBadRequest, "validation_error", "'version' is required", nil)
			return
		}
		if req.Content == "" {
			writeOPAError(w, http.StatusBadRequest, "validation_error", "'content' is required", nil)
			return
		}

		// Verify the policy compiles before storing it.
		if _, err := dep.Engine.Eval(r.Context(), EvalOptions{
			PolicyText: req.Content,
			DataMap:    map[string]any{},
			Input:      map[string]any{},
			Query:      "data.authz.allow",
		}); err != nil {
			var ce *CompileError
			if errors.As(err, &ce) {
				writeOPAError(w, http.StatusBadRequest, "compile_error", ce.Message, &errorMeta{File: "policy.rego"})
				return
			}
		}

		p := domain.Policy{
			ID:          newPolicyID(),
			Name:        req.Name,
			Version:     req.Version,
			Content:     req.Content,
			ContentHash: policyContentHash(req.Content),
			CreatedAt:   time.Now().UTC(),
		}
		created, err := dep.Policies.Create(p)
		if err != nil {
			writeOPAError(w, http.StatusInternalServerError, "server_error", err.Error(), nil)
			return
		}
		writeJSON(w, http.StatusCreated, policyToResponse(created))
	}
}

func getPolicyHandler(dep RouterDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		p, err := dep.Policies.GetByID(id)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeOPAError(w, http.StatusNotFound, "not_found", "policy not found", nil)
				return
			}
			writeOPAError(w, http.StatusInternalServerError, "server_error", err.Error(), nil)
			return
		}
		writeJSON(w, http.StatusOK, policyToResponse(p))
	}
}

func deletePolicyHandler(dep RouterDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		if err := dep.Policies.Delete(id); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeOPAError(w, http.StatusNotFound, "not_found", "policy not found", nil)
				return
			}
			writeOPAError(w, http.StatusInternalServerError, "server_error", err.Error(), nil)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func activatePolicyHandler(dep RouterDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		now := time.Now().UTC()
		if err := dep.Policies.Activate(id, now); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeOPAError(w, http.StatusNotFound, "not_found", "policy not found", nil)
				return
			}
			writeOPAError(w, http.StatusInternalServerError, "server_error", err.Error(), nil)
			return
		}
		p, err := dep.Policies.GetByID(id)
		if err != nil {
			writeOPAError(w, http.StatusInternalServerError, "server_error", err.Error(), nil)
			return
		}
		writeJSON(w, http.StatusOK, ActivateResponse{
			ID:          p.ID,
			Name:        p.Name,
			Version:     p.Version,
			Active:      p.Active,
			ActivatedAt: now,
		})
	}
}

func policyToResponse(p domain.Policy) PolicyResponse {
	return PolicyResponse{
		ID:          p.ID,
		Name:        p.Name,
		Version:     p.Version,
		Content:     p.Content,
		ContentHash: p.ContentHash,
		Active:      p.Active,
		CreatedAt:   p.CreatedAt,
		ActivatedAt: p.ActivatedAt,
	}
}

func newPolicyID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "pol_" + hex.EncodeToString(b)
}

func policyContentHash(content string) string {
	sum := sha256.Sum256([]byte(content))
	return fmt.Sprintf("%x", sum)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func buildInputForRequest(dep RouterDeps, req EvaluateRequest) (map[string]any, error) {
	if req.UserID != "" {
		user, err := resolveUser(dep, req.UserID)
		if err != nil {
			return nil, err
		}
		p := personality.Default
		if req.Provider != "" && req.Provider != "all" {
			if pp, ok := personality.Get(req.Provider); ok {
				p = pp
			}
		}
		baseClaims := userToClaims(user)
		shaped := p.Apply(baseClaims)
		return BuildInput(map[string]any{"user": shaped}, req.Action, req.Resource, req.Context), nil
	}
	base := make(map[string]any)
	for k, v := range req.Input {
		base[k] = v
	}
	return BuildInput(base, req.Action, req.Resource, req.Context), nil
}

func buildBatchBaseInput(dep RouterDeps, req BatchRequest) (map[string]any, error) {
	if req.UserID != "" {
		user, err := resolveUser(dep, req.UserID)
		if err != nil {
			return nil, err
		}
		p := personality.Default
		if req.Provider != "" {
			if pp, ok := personality.Get(req.Provider); ok {
				p = pp
			}
		}
		shaped := p.Apply(userToClaims(user))
		return map[string]any{"user": shaped}, nil
	}
	return map[string]any{}, nil
}

func resolveUser(dep RouterDeps, userID string) (domain.User, error) {
	if dep.Users == nil {
		return domain.User{}, fmt.Errorf("user store not available")
	}
	user, err := dep.Users.GetByID(userID)
	if err != nil {
		return domain.User{}, fmt.Errorf("user %q not found", userID)
	}
	return user, nil
}

func userToClaims(user domain.User) map[string]any {
	claims := map[string]any{
		"sub":    user.ID,
		"email":  user.Email,
		"name":   user.DisplayName,
		"groups": user.Groups,
	}
	for k, v := range user.Claims {
		if _, exists := claims[k]; !exists {
			claims[k] = v
		}
	}
	return map[string]any{"claims": claims, "roles": user.Groups}
}

func buildEvaluateResponse(result EvalResult, query string, input map[string]any, withTrace bool) EvaluateResponse {
	resp := EvaluateResponse{
		Allow:               result.Allow,
		Query:               query,
		PolicyVersion:       "inline", // overwritten by evaluateHandler when using a named policy
		EvaluationTimestamp: time.Now().UTC(),
		Bindings:            map[string]any{},
	}

	if !result.Defined {
		resp.Decision = "undefined"
	} else if result.Allow {
		resp.Decision = "grant"
	} else {
		resp.Decision = "deny"
	}

	// If the result is a structured decision document, extract denial_reason and permission_state.
	if result.Bindings != nil {
		if state, ok := result.Bindings["state"].(string); ok {
			resp.PermissionState = state
		}
		if reason, ok := result.Bindings["reason"].(string); ok && reason != "" {
			resp.DenialReason = reason
		}
		resp.Bindings = result.Bindings
	}

	resp.InputUsed = input
	if withTrace {
		resp.Trace = result.Trace
	}
	return resp
}

// applyTimeoutOverride sets opts timeouts to the per-tenant budget and then
// allows the request to tighten them further via ov. It never loosens limits:
// if ov requests a longer timeout than the budget allows, it is ignored.
func applyTimeoutOverride(opts *EvalOptions, ov *TimeoutOverride, budget config.OPATenantBudget) {
	opts.CompileTimeout = budget.CompileTimeout
	opts.EvalTimeout = budget.EvalTimeout
	if ov == nil {
		return
	}
	if ov.CompileMS > 0 {
		requested := time.Duration(ov.CompileMS) * time.Millisecond
		if requested < opts.CompileTimeout {
			opts.CompileTimeout = requested
		}
	}
	if ov.EvalMS > 0 {
		requested := time.Duration(ov.EvalMS) * time.Millisecond
		if requested < opts.EvalTimeout {
			opts.EvalTimeout = requested
		}
	}
}

func validateEvaluateReq(req EvaluateRequest) error {
	if req.Policy != "" && req.PolicyName != "" {
		return errors.New("supply exactly one of 'policy' or 'policy_name', not both")
	}
	if req.Policy == "" && req.PolicyName == "" {
		return errors.New("supply exactly one of 'policy' or 'policy_name'")
	}
	if req.Input != nil && req.UserID != "" {
		return errors.New("supply exactly one of 'input' or 'user_id', not both")
	}
	return nil
}

func diffClaims(a, b map[string]any) []ClaimDiff {
	var diffs []ClaimDiff
	for k, av := range a {
		if bv, ok := b[k]; ok {
			if fmt.Sprint(av) != fmt.Sprint(bv) {
				diffs = append(diffs, ClaimDiff{Path: k, FurnaceValue: av, ProviderValue: bv})
			}
		}
	}
	return diffs
}

func writeEvalError(w http.ResponseWriter, err error) {
	var ce *CompileError
	var cte *CompileTimeoutError
	var ete *EvalTimeoutError
	switch {
	case errors.As(err, &ce):
		writeOPAError(w, http.StatusBadRequest, "compile_error", ce.Message, &errorMeta{File: "policy.rego"})
	case errors.As(err, &cte):
		writeOPAError(w, http.StatusRequestTimeout, "compile_timeout", "compilation exceeded deadline", &errorMeta{Phase: "compile"})
	case errors.As(err, &ete):
		writeOPAError(w, http.StatusRequestTimeout, "eval_timeout", "evaluation exceeded deadline", &errorMeta{Phase: "eval"})
	default:
		writeOPAError(w, http.StatusInternalServerError, "server_error", err.Error(), nil)
	}
}

func writeOPAError(w http.ResponseWriter, status int, code, message string, meta *errorMeta) {
	writeJSON(w, status, errorResponse{Error: errorDetail{Code: code, Message: message, Details: meta}})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeOPAError(w, http.StatusBadRequest, "validation_error", "invalid JSON: "+err.Error(), nil)
		return false
	}
	return true
}

// ---- diff helpers ----

func mapField(m map[string]any, key string) map[string]any {
	v, ok := m[key]
	if !ok {
		return map[string]any{}
	}
	r, ok := v.(map[string]any)
	if !ok {
		return map[string]any{}
	}
	return r
}

func stringKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func unionKeys(a, b map[string]any) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	for k := range a {
		seen[k] = struct{}{}
	}
	for k := range b {
		seen[k] = struct{}{}
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func setDiff(after, before []string) (added, removed []string) {
	bset := make(map[string]struct{}, len(before))
	for _, v := range before {
		bset[v] = struct{}{}
	}
	aset := make(map[string]struct{}, len(after))
	for _, v := range after {
		aset[v] = struct{}{}
	}
	for _, v := range after {
		if _, ok := bset[v]; !ok {
			added = append(added, v)
		}
	}
	for _, v := range before {
		if _, ok := aset[v]; !ok {
			removed = append(removed, v)
		}
	}
	return added, removed
}

func bumpMax(current, candidate string) string {
	order := map[string]int{"none": 0, "patch": 1, "minor": 2, "major": 3}
	if order[candidate] > order[current] {
		return candidate
	}
	return current
}
