package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"authpilot/server/internal/domain"
	"authpilot/server/internal/store/memory"
)

// fakeMinter is a test double for TokenMinter.
type fakeMinter struct {
	called    bool
	returnErr bool
}

func (f *fakeMinter) MintForUser(user domain.User, clientID string, scopes []string, expiresIn int) (MintedTokens, error) {
	f.called = true
	if f.returnErr {
		return MintedTokens{}, errors.New("signing failed")
	}
	return MintedTokens{
		AccessToken: "at." + user.ID,
		IDToken:     "idt." + user.ID,
		ExpiresIn:   expiresIn,
	}, nil
}

func newMintRouter(minter TokenMinter) http.Handler {
	users := memory.NewUserStore()
	_, _ = users.Create(domain.User{ID: "usr_mint_01", Email: "mint@example.com"})
	return NewRouter(Dependencies{
		Users:       users,
		Groups:      memory.NewGroupStore(),
		Flows:       memory.NewFlowStore(),
		Sessions:    memory.NewSessionStore(),
		TokenMinter: minter,
	})
}

func TestMintToken_Success(t *testing.T) {
	minter := &fakeMinter{}
	router := newMintRouter(minter)

	body := `{"user_id":"usr_mint_01","client_id":"ci-client","scopes":["openid","email"],"expires_in":1800}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tokens/mint", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp MintedTokens
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.AccessToken != "at.usr_mint_01" {
		t.Errorf("access_token: got %q", resp.AccessToken)
	}
	if resp.IDToken != "idt.usr_mint_01" {
		t.Errorf("id_token: got %q", resp.IDToken)
	}
	if resp.ExpiresIn != 1800 {
		t.Errorf("expires_in: got %d, want 1800", resp.ExpiresIn)
	}
	if !minter.called {
		t.Error("minter was not called")
	}
}

func TestMintToken_MissingUserID(t *testing.T) {
	router := newMintRouter(&fakeMinter{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tokens/mint", bytes.NewBufferString(`{"client_id":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
	var body map[string]any
	_ = json.NewDecoder(rr.Body).Decode(&body)
	errObj, _ := body["error"].(map[string]any)
	if errObj["code"] != "INVALID_REQUEST" {
		t.Errorf("expected INVALID_REQUEST, got %v", errObj["code"])
	}
}

func TestMintToken_UserNotFound(t *testing.T) {
	router := newMintRouter(&fakeMinter{})

	body := `{"user_id":"no_such_user"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tokens/mint", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
	var b map[string]any
	_ = json.NewDecoder(rr.Body).Decode(&b)
	errObj, _ := b["error"].(map[string]any)
	if errObj["code"] != "RESOURCE_NOT_FOUND" {
		t.Errorf("expected RESOURCE_NOT_FOUND, got %v", errObj["code"])
	}
}

func TestMintToken_MinterError(t *testing.T) {
	router := newMintRouter(&fakeMinter{returnErr: true})

	body := `{"user_id":"usr_mint_01"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tokens/mint", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

func TestMintToken_NilMinter_Returns501(t *testing.T) {
	router := newMintRouter(nil)

	body := `{"user_id":"usr_mint_01"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tokens/mint", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotImplemented {
		t.Errorf("expected 501, got %d", rr.Code)
	}
}

func TestMintToken_DefaultExpiresIn(t *testing.T) {
	minter := &fakeMinter{}
	router := newMintRouter(minter)

	// expires_in omitted — should default to 3600
	body := `{"user_id":"usr_mint_01"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tokens/mint", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp MintedTokens
	_ = json.NewDecoder(rr.Body).Decode(&resp)
	if resp.ExpiresIn != 3600 {
		t.Errorf("expected default expires_in=3600, got %d", resp.ExpiresIn)
	}
}
