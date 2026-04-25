package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"

	"furnace/server/internal/store"
)

// tokenCompareHandler implements GET /api/v1/debug/token-compare.
//
// Accepts two JWT strings — one from Furnace and one from a real provider —
// and returns a structured diff of their claim sets. No signature verification
// is performed; this is a dev/debug tool only.
//
// Query params:
//   - furnace_token: JWT issued by this Furnace instance
//   - provider_token:  JWT from the real provider (Okta, Azure AD, etc.)
//
// Optional:
//   - flow_id: if supplied, verifies the flow exists (helps correlate context)
func tokenCompareHandler(flows store.FlowStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		furnaceToken := strings.TrimSpace(r.URL.Query().Get("furnace_token"))
		providerToken := strings.TrimSpace(r.URL.Query().Get("provider_token"))
		flowID := strings.TrimSpace(r.URL.Query().Get("flow_id"))

		if furnaceToken == "" {
			writeAPIError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "furnace_token is required", false)
			return
		}
		if providerToken == "" {
			writeAPIError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "provider_token is required", false)
			return
		}

		// Optional flow context check.
		if flowID != "" {
			if _, err := flows.GetByID(flowID); err != nil {
				writeAPIError(w, r, http.StatusNotFound, "RESOURCE_NOT_FOUND", "flow not found", false)
				return
			}
		}

		furnaceClaims, err := decodeJWTClaims(furnaceToken)
		if err != nil {
			writeAPIError(w, r, http.StatusUnprocessableEntity, "DECODE_FAILED",
				fmt.Sprintf("could not decode furnace_token: %v", err), false)
			return
		}

		providerClaims, err := decodeJWTClaims(providerToken)
		if err != nil {
			writeAPIError(w, r, http.StatusUnprocessableEntity, "DECODE_FAILED",
				fmt.Sprintf("could not decode provider_token: %v", err), false)
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"furnace_token": furnaceClaims,
			"provider_token":  providerClaims,
			"differences":     diffClaims(furnaceClaims, providerClaims),
		})
	}
}

// ClaimDiff describes a single claim difference between two tokens.
type ClaimDiff struct {
	Path            string `json:"path"`
	FurnaceValue  any    `json:"furnace_value"`
	ProviderValue   any    `json:"provider_value"`
	Note            string `json:"note"`
}

// diffClaims compares two claim maps and returns a list of differences.
// Nested objects are traversed recursively; paths use dot notation (e.g. "address.street_address").
func diffClaims(furnace, provider map[string]any) []ClaimDiff {
	var diffs []ClaimDiff
	diffClaimsAt("", furnace, provider, &diffs)
	if diffs == nil {
		diffs = []ClaimDiff{}
	}
	return diffs
}

func diffClaimsAt(prefix string, furnace, provider map[string]any, diffs *[]ClaimDiff) {
	seen := make(map[string]bool)

	for k, av := range furnace {
		seen[k] = true
		path := claimPath(prefix, k)
		pv, ok := provider[k]
		if !ok {
			*diffs = append(*diffs, ClaimDiff{
				Path:          path,
				FurnaceValue:  av,
				ProviderValue: nil,
				Note:          "present in furnace token, missing in provider token",
			})
			continue
		}

		aMap, aIsMap := av.(map[string]any)
		pMap, pIsMap := pv.(map[string]any)
		if aIsMap && pIsMap {
			diffClaimsAt(path, aMap, pMap, diffs)
			continue
		}

		at, pt := jsonTypeName(av), jsonTypeName(pv)
		if at != pt {
			*diffs = append(*diffs, ClaimDiff{
				Path:          path,
				FurnaceValue:  av,
				ProviderValue: pv,
				Note:          fmt.Sprintf("type mismatch: furnace has %s, provider has %s", at, pt),
			})
			continue
		}

		if !jsonEqual(av, pv) {
			*diffs = append(*diffs, ClaimDiff{
				Path:          path,
				FurnaceValue:  av,
				ProviderValue: pv,
				Note:          "values differ",
			})
		}
	}

	for k, pv := range provider {
		if seen[k] {
			continue
		}
		*diffs = append(*diffs, ClaimDiff{
			Path:          claimPath(prefix, k),
			FurnaceValue:  nil,
			ProviderValue: pv,
			Note:          "missing in furnace token, present in provider token",
		})
	}
}

func claimPath(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

// jsonTypeName returns the JSON type name for a Go value decoded from JSON.
func jsonTypeName(v any) string {
	switch v.(type) {
	case string:
		return "string"
	case float64:
		return "number"
	case bool:
		return "boolean"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	case nil:
		return "null"
	default:
		return fmt.Sprintf("%T", v)
	}
}

// jsonEqual compares two JSON-decoded values by re-marshaling them.
func jsonEqual(a, b any) bool {
	aj, _ := json.Marshal(a)
	bj, _ := json.Marshal(b)
	return string(aj) == string(bj)
}

// decodeJWTClaims decodes the claims from a JWT without verifying the signature.
// Safe for dev/debug use only.
func decodeJWTClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a valid JWT (expected 3 parts, got %d)", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal claims: %w", err)
	}
	return claims, nil
}

// registerDebugRoutes adds debug-only endpoints to the API subrouter.
// These are always registered — callers should gate them with an API key.
func registerDebugRoutes(api *mux.Router, dep *Dependencies) {
	api.HandleFunc("/debug/token-compare", func(w http.ResponseWriter, r *http.Request) {
		_, _, flows, _, _ := dep.resolveStores(r.Context())
		tokenCompareHandler(flows)(w, r)
	}).Methods(http.MethodGet)
}
