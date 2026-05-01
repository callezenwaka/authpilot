package httpapi

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"furnace/server/internal/domain"
	"furnace/server/internal/store"
)

// validScopes is the set of scopes callers may request on a new key.
var validScopes = map[string]bool{
	"read":          true,
	"write":         true,
	"admin":         true,
	"opa:emergency": true,
}

type apiKeyCreateRequest struct {
	Label  string   `json:"label"`
	Scopes []string `json:"scopes"`
}

type apiKeyCreateResponse struct {
	ID        string    `json:"id"`
	Label     string    `json:"label"`
	Key       string    `json:"key"` // raw value — shown once only
	Scopes    []string  `json:"scopes"`
	CreatedAt time.Time `json:"created_at"`
}

type apiKeyResponse struct {
	ID         string     `json:"id"`
	Label      string     `json:"label"`
	Scopes     []string   `json:"scopes"`
	CreatedAt  time.Time  `json:"created_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

func listAPIKeysHandler(ks store.APIKeyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		keys, err := ks.List()
		if err != nil {
			writeAPIError(w, r, http.StatusInternalServerError, "SERVER_ERROR", err.Error(), false)
			return
		}
		out := make([]apiKeyResponse, len(keys))
		for i, k := range keys {
			out[i] = toAPIKeyResponse(k)
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func createAPIKeyHandler(ks store.APIKeyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req apiKeyCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAPIError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "invalid JSON body", false)
			return
		}
		if req.Label == "" {
			writeAPIError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "'label' is required", false)
			return
		}
		if len(req.Scopes) == 0 {
			req.Scopes = []string{"read", "write"}
		}
		for _, s := range req.Scopes {
			if !validScopes[s] {
				writeAPIError(w, r, http.StatusBadRequest, "INVALID_REQUEST",
					fmt.Sprintf("unknown scope %q; valid: read, write, admin, opa:emergency", s), false)
				return
			}
		}

		rawKey, keyHash, err := generateAPIKey()
		if err != nil {
			writeAPIError(w, r, http.StatusInternalServerError, "SERVER_ERROR", "key generation failed", false)
			return
		}

		k := domain.APIKey{
			ID:        newAPIKeyID(),
			Label:     req.Label,
			KeyHash:   keyHash,
			Scopes:    req.Scopes,
			CreatedAt: time.Now().UTC(),
		}
		created, err := ks.Create(k)
		if err != nil {
			writeAPIError(w, r, http.StatusInternalServerError, "SERVER_ERROR", err.Error(), false)
			return
		}

		writeJSON(w, http.StatusCreated, apiKeyCreateResponse{
			ID:        created.ID,
			Label:     created.Label,
			Key:       rawKey,
			Scopes:    created.Scopes,
			CreatedAt: created.CreatedAt,
		})
	}
}

func getAPIKeyHandler(ks store.APIKeyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		k, err := ks.GetByID(id)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeAPIError(w, r, http.StatusNotFound, "NOT_FOUND", "api key not found", false)
				return
			}
			writeAPIError(w, r, http.StatusInternalServerError, "SERVER_ERROR", err.Error(), false)
			return
		}
		writeJSON(w, http.StatusOK, toAPIKeyResponse(k))
	}
}

func revokeAPIKeyHandler(ks store.APIKeyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		if err := ks.Revoke(id, time.Now().UTC()); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeAPIError(w, r, http.StatusNotFound, "NOT_FOUND", "api key not found or already revoked", false)
				return
			}
			writeAPIError(w, r, http.StatusInternalServerError, "SERVER_ERROR", err.Error(), false)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// ---- helpers ----

func toAPIKeyResponse(k domain.APIKey) apiKeyResponse {
	return apiKeyResponse{
		ID:         k.ID,
		Label:      k.Label,
		Scopes:     k.Scopes,
		CreatedAt:  k.CreatedAt,
		RevokedAt:  k.RevokedAt,
		LastUsedAt: k.LastUsedAt,
	}
}

func generateAPIKey() (rawKey, hash string, err error) {
	b := make([]byte, 24)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	rawKey = "furn_" + hex.EncodeToString(b)
	sum := sha256.Sum256([]byte(rawKey))
	hash = hex.EncodeToString(sum[:])
	return rawKey, hash, nil
}

func newAPIKeyID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "ak_" + hex.EncodeToString(b)
}

// APIKeyHash returns the SHA-256 hex hash of a raw key string.
// Used by the auth middleware to look up DB keys.
func APIKeyHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
