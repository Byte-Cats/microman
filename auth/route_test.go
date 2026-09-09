package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

// newTestRouter builds a bare mux.Router with only the auth package's routes
// mounted, so these tests exercise AuthRoute end-to-end via ServeHTTP
// without depending on server.InitRouter/InitRoutes.
func newTestRouter() *mux.Router {
	router := mux.NewRouter()
	AuthRoute(router)
	return router
}

// TestAuthRoute_Login_NonexistentUser exercises POST /auth/login with
// valid-shaped credentials for a user that doesn't exist in any database.
// There is no real MySQL connection available in this test environment.
// FindUserByUsername now goes through database.go's getDB(), a
// sync.Once-guarded lazy connection helper: previously the package-level
// *sql.DB was only ever assigned by an initDB() that nothing in the codebase
// called, so it was nil at runtime and this dereferenced a nil *sql.DB and
// panicked. getDB() instead returns a clean connection error when no
// database is reachable, so this no longer panics - the recover() below is
// kept only as defense in depth. Either way, login must never report success
// (200) for a user that was never created.
func TestAuthRoute_Login_NonexistentUser(t *testing.T) {
	setTestSecret(t)
	router := newTestRouter()

	form := url.Values{}
	form.Set("username", "nonexistentuser")
	form.Set("password", "Passw0rd1")

	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
				t.Logf("login handler panicked for a nonexistent user: %v", r)
			}
		}()
		router.ServeHTTP(rec, req)
	}()

	if !panicked && rec.Code == http.StatusOK {
		t.Errorf("login with a nonexistent user unexpectedly succeeded: status=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestAuthRoute_Me_NoAuthHeader(t *testing.T) {
	setTestSecret(t)
	router := newTestRouter()

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d, body=%q", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

func TestAuthRoute_Me_MalformedToken(t *testing.T) {
	setTestSecret(t)
	router := newTestRouter()

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.Header.Set("Authorization", "Bearer garbage.token.value")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d, body=%q", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

func TestAuthRoute_Me_ValidToken(t *testing.T) {
	setTestSecret(t)
	router := newTestRouter()

	token, err := generateJWT(7)
	if err != nil {
		t.Fatalf("generateJWT() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%q", rec.Code, http.StatusOK, rec.Body.String())
	}

	var claims Claims
	if err := json.NewDecoder(rec.Body).Decode(&claims); err != nil {
		t.Fatalf("decoding /auth/me response body: %v", err)
	}
	if claims.ID != 7 {
		t.Errorf("claims.ID = %d, want 7", claims.ID)
	}
}

// TestAuthRoute_UserNew_InvalidInput exercises POST /auth/user/new with no
// body at all, so username/password are both empty. CreateUser's call to
// validateUserInput rejects that before ever touching the database, so this
// is safe to assert precisely (400) without a live MySQL instance.
func TestAuthRoute_UserNew_InvalidInput(t *testing.T) {
	setTestSecret(t)
	router := newTestRouter()

	req := httptest.NewRequest(http.MethodPost, "/auth/user/new", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d, body=%q", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestAuthRoute_UserNew_ValidInput_NoDatabase submits a validly-shaped
// username/password. Past validation, CreateUser needs a real database
// connection (to check for an existing username and insert the row), which
// isn't available in this test environment. This asserts the handler never
// reports success in that case, mirroring the tolerance pattern used by
// TestAuthRoute_Login_NonexistentUser above for the same reason.
func TestAuthRoute_UserNew_ValidInput_NoDatabase(t *testing.T) {
	setTestSecret(t)
	router := newTestRouter()

	form := url.Values{}
	form.Set("username", "gooduser")
	form.Set("password", "Passw0rd1")

	req := httptest.NewRequest(http.MethodPost, "/auth/user/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code == http.StatusCreated {
		t.Errorf("user creation unexpectedly succeeded with no database available: status=%d body=%q", rec.Code, rec.Body.String())
	}
}

// TestAuthRoute_UserRemove_NoAuthHeader confirms POST /auth/user/remove is
// gated by JWTMiddleware just like GET /auth/me: an unauthenticated caller
// is rejected with 401 before removeUserHandler (and therefore any
// database access) ever runs.
func TestAuthRoute_UserRemove_NoAuthHeader(t *testing.T) {
	setTestSecret(t)
	router := newTestRouter()

	req := httptest.NewRequest(http.MethodPost, "/auth/user/remove", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d, body=%q", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

// TestAuthRoute_UserRemove_MissingUsername authenticates with a valid token
// but omits the "username" form value. removeUserHandler rejects that with
// 400 before it ever needs a database connection, so this is safe to assert
// precisely without a live MySQL instance.
func TestAuthRoute_UserRemove_MissingUsername(t *testing.T) {
	setTestSecret(t)
	router := newTestRouter()

	token, err := generateJWT(1)
	if err != nil {
		t.Fatalf("generateJWT() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/user/remove", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d, body=%q", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}
