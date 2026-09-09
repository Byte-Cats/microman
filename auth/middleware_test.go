package auth

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
)

// testSecretPlain is an arbitrary plaintext secret used only by tests.
// FindSecret hex-decodes the SECRET env var, so tests must set SECRET to
// the hex-encoded form of whatever plaintext secret they want to sign with.
const testSecretPlain = "unit-test-signing-secret-for-microman"

// setTestSecret configures the SECRET env var (hex-encoded, as FindSecret
// requires) for the duration of t, so generateJWT/VerifyToken work without a
// real deployment secret.
func setTestSecret(t *testing.T) {
	t.Helper()
	t.Setenv("SECRET", hex.EncodeToString([]byte(testSecretPlain)))
}

func TestJWTMiddleware_MissingHeader(t *testing.T) {
	setTestSecret(t)
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	handler := JWTMiddleware(next)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if called {
		t.Error("next handler should not have been called for a request with no Authorization header")
	}
}

func TestJWTMiddleware_MalformedToken(t *testing.T) {
	setTestSecret(t)
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	handler := JWTMiddleware(next)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer this-is-not-a-jwt")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if called {
		t.Error("next handler should not have been called for a malformed bearer token")
	}
}

func TestJWTMiddleware_ValidToken(t *testing.T) {
	setTestSecret(t)
	token, err := generateJWT(42)
	if err != nil {
		t.Fatalf("generateJWT() error = %v", err)
	}

	var gotClaims *Claims
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := ClaimsFromContext(r.Context())
		if !ok {
			t.Error("claims not found on request context inside protected handler")
		}
		gotClaims = claims
		w.WriteHeader(http.StatusOK)
	})
	handler := JWTMiddleware(next)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if gotClaims == nil || gotClaims.ID != 42 {
		t.Errorf("claims = %+v, want ID = 42", gotClaims)
	}
}
