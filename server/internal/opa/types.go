package opa

import "time"

// EvaluateRequest is the body for POST /api/v1/opa/evaluate.
type EvaluateRequest struct {
	Policy     string         `json:"policy"`      // inline Rego; mutually exclusive with PolicyName
	PolicyName string         `json:"policy_name"` // stored policy; mutually exclusive with Policy
	Data       map[string]any `json:"data"`
	Input      map[string]any `json:"input"`    // raw input; mutually exclusive with UserID
	UserID     string         `json:"user_id"`  // resolved to input.user by Furnace
	Action     string         `json:"action"`
	Resource   string         `json:"resource"`
	Context    map[string]any `json:"context"`
	Provider   string         `json:"provider"` // "" | "okta" | "azure-ad" | "google" | "github" | "all"
	Query      string         `json:"query"`    // defaults to "data.authz.allow"
	Trace      bool           `json:"trace"`
	Timeouts   *TimeoutOverride `json:"timeouts"`
}

// TimeoutOverride allows per-request timeout caps (capped at server maximum).
type TimeoutOverride struct {
	CompileMS int `json:"compile_ms"`
	EvalMS    int `json:"eval_ms"`
}

// EvaluateResponse is the body returned by POST /api/v1/opa/evaluate.
type EvaluateResponse struct {
	Allow               bool           `json:"allow"`
	Decision            string         `json:"decision"`             // "grant" | "deny" | "undefined" | "error"
	Query               string         `json:"query"`
	PermissionState     string         `json:"permission_state,omitempty"`
	DenialReason        string         `json:"denial_reason,omitempty"`
	InputUsed           map[string]any `json:"input_used,omitempty"`
	Bindings            map[string]any `json:"bindings,omitempty"`
	PolicyVersion       string         `json:"policy_version"`
	EvaluationTimestamp time.Time      `json:"evaluation_timestamp"`
	Trace               []TraceEvent   `json:"trace,omitempty"`
}

// MultiProviderEvaluateResponse is returned when provider=="all".
type MultiProviderEvaluateResponse struct {
	ResultsByProvider   map[string]ProviderResult `json:"results_by_provider"`
	ProvidersPass       []string                  `json:"providers_passing"`
	ProvidersFail       []string                  `json:"providers_failing"`
	Recommendation      string                    `json:"recommendation,omitempty"`
	EvaluationTimestamp time.Time                 `json:"evaluation_timestamp"`
}

// ProviderResult is one entry in a multi-provider response.
type ProviderResult struct {
	Allow    bool   `json:"allow"`
	Decision string `json:"decision"`
	Error    string `json:"error,omitempty"`
}

// TraceEvent is one step in an OPA trace.
type TraceEvent struct {
	Op   string `json:"op"`
	Node string `json:"node"`
}

// BatchRequest is the body for POST /api/v1/opa/evaluate/batch.
type BatchRequest struct {
	Policy     string         `json:"policy"`
	PolicyName string         `json:"policy_name"`
	Data       map[string]any `json:"data"`
	UserID     string         `json:"user_id"`
	Context    map[string]any `json:"context"`
	Provider   string         `json:"provider"`
	Query      string         `json:"query"`
	Checks     []BatchCheck   `json:"checks"`
	Timeouts   *TimeoutOverride `json:"timeouts"`
}

// BatchCheck is one action+resource pair inside a batch request.
type BatchCheck struct {
	Action   string `json:"action"`
	Resource string `json:"resource"`
}

// BatchResponse is the body returned by POST /api/v1/opa/evaluate/batch.
type BatchResponse struct {
	UserID              string        `json:"user_id,omitempty"`
	UserRoles           []string      `json:"user_roles,omitempty"`
	Context             map[string]any `json:"context,omitempty"`
	TotalChecks         int           `json:"total_checks"`
	Grant               int           `json:"grant"`
	Deny                int           `json:"deny"`
	Results             []BatchResult `json:"results"`
	EvaluationTimestamp time.Time     `json:"evaluation_timestamp"`
}

// BatchResult is one check outcome inside a BatchResponse.
type BatchResult struct {
	Action   string `json:"action"`
	Resource string `json:"resource"`
	Allow    bool   `json:"allow"`
	Decision string `json:"decision"`
	Error    string `json:"error,omitempty"`
}

// ValidateRequest is the body for POST /api/v1/opa/validate.
type ValidateRequest struct {
	Data   map[string]any `json:"data"`
	Schema string         `json:"schema"` // "" | "tristate"
}

// ValidateResponse is the body returned by POST /api/v1/opa/validate.
type ValidateResponse struct {
	Valid    bool     `json:"valid"`
	Errors   []string `json:"errors"`
	Warnings []string `json:"warnings"`
}

// DiffRequest is the body for POST /api/v1/opa/diff.
type DiffRequest struct {
	Before map[string]any `json:"before"`
	After  map[string]any `json:"after"`
}

// DiffResponse is the body returned by POST /api/v1/opa/diff.
type DiffResponse struct {
	AddedRoles          []string       `json:"added_roles"`
	RemovedRoles        []string       `json:"removed_roles"`
	AddedSystems        []string       `json:"added_systems"`
	RemovedSystems      []string       `json:"removed_systems"`
	AddedPermissions    []string       `json:"added_permissions"`
	RemovedPermissions  []string       `json:"removed_permissions"`
	ChangedPermissions  []PermChange   `json:"changed_permissions"`
	RecommendedBump     string         `json:"recommended_bump"` // "major" | "minor" | "patch" | "none"
	Summary             string         `json:"summary"`
}

// PermChange describes changed permission entries for one resource.
type PermChange struct {
	Resource string                     `json:"resource"`
	Changes  map[string]RolePermChanges `json:"changes"`
}

// RolePermChanges holds before/after for each action in one role.
type RolePermChanges struct {
	Old map[string]any `json:"old"`
	New map[string]any `json:"new"`
}

// TokenPipelineRequest is the body for POST /api/v1/opa/evaluate/token-pipeline.
type TokenPipelineRequest struct {
	Policy        string         `json:"policy"`
	PolicyName    string         `json:"policy_name"`
	Data          map[string]any `json:"data"`
	FurnaceToken  string         `json:"furnace_token"`
	ProviderToken string         `json:"provider_token"`
	Action        string         `json:"action"`
	Resource      string         `json:"resource"`
	Context       map[string]any `json:"context"`
	Query         string         `json:"query"`
	Timeouts      *TimeoutOverride `json:"timeouts"`
}

// TokenPipelineResponse is the body returned by the token pipeline endpoint.
type TokenPipelineResponse struct {
	FurnaceResult    *TokenPipelineResult `json:"furnace_result,omitempty"`
	ProviderResult   *TokenPipelineResult `json:"provider_result,omitempty"`
	DecisionMatches  bool                 `json:"decision_matches"`
	ClaimDifferences []ClaimDiff          `json:"claim_differences,omitempty"`
	Recommendation   string               `json:"recommendation,omitempty"`
	Query            string               `json:"query"`
	EvaluationTimestamp time.Time         `json:"evaluation_timestamp"`
}

// TokenPipelineResult is one token's evaluation outcome in a pipeline response.
type TokenPipelineResult struct {
	Allow      bool           `json:"allow"`
	Decision   string         `json:"decision"`
	ClaimsUsed map[string]any `json:"claims_used,omitempty"`
	Error      string         `json:"error,omitempty"`
}

// ClaimDiff describes a claim value that differs between two tokens.
type ClaimDiff struct {
	Path           string `json:"path"`
	FurnaceValue   any    `json:"furnace_value"`
	ProviderValue  any    `json:"provider_value"`
	Note           string `json:"note,omitempty"`
}

// HealthResponse is returned by GET /api/v1/opa/health.
type HealthResponse struct {
	Status           string   `json:"status"`
	Engine           string   `json:"engine"`
	OPAVersion       string   `json:"opa_version"`
	EvaluationTest   string   `json:"evaluation_test"`
	DisabledBuiltins []string `json:"disabled_builtins"`
}

// PolicyCreateRequest is the body for POST /api/v1/opa/policies.
type PolicyCreateRequest struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Content string `json:"content"`
}

// PolicyResponse is returned by policy CRUD endpoints.
type PolicyResponse struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Version     string     `json:"version"`
	Content     string     `json:"content"`
	ContentHash string     `json:"content_hash"`
	Active      bool       `json:"active"`
	CreatedAt   time.Time  `json:"created_at"`
	ActivatedAt *time.Time `json:"activated_at,omitempty"`
}

// PolicyListResponse is returned by GET /api/v1/opa/policies.
type PolicyListResponse struct {
	Policies []PolicyResponse `json:"policies"`
	Total    int              `json:"total"`
}

// ActivateResponse is returned by POST /api/v1/opa/policies/{id}/activate.
type ActivateResponse struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	Active      bool      `json:"active"`
	ActivatedAt time.Time `json:"activated_at"`
}

// errorResponse is the standard error envelope for all non-2xx OPA responses.
type errorResponse struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    string      `json:"code"`
	Message string      `json:"message"`
	Details *errorMeta  `json:"details,omitempty"`
}

type errorMeta struct {
	File   string `json:"file,omitempty"`
	Line   int    `json:"line,omitempty"`
	Column int    `json:"column,omitempty"`
	Phase  string `json:"phase,omitempty"` // "compile" | "eval"
}
