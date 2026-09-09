package auth

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gorilla/mux"
)

// AuthRoute mounts the auth package's routes and middleware onto router.
//
//   - POST /auth/login       public, exchanges valid credentials for a JWT.
//   - GET  /auth/me          protected by JWTMiddleware, echoes the caller's
//     verified claims back as JSON; this is the demonstration of the JWT
//     middleware actually gating a route end-to-end.
//   - POST /auth/user/new    public, creates a new user account via
//     CreateUser. Registration has to be reachable by callers who don't have
//     a token yet, same as login.
//   - POST /auth/user/remove protected by JWTMiddleware: an unauthenticated
//     "delete any account by username" endpoint would be a real security
//     hole even in a demo project, so the caller must present a valid JWT
//     and may only remove the account that JWT was issued for.
func AuthRoute(router *mux.Router) {
	router.HandleFunc("/auth/login", LoginHandler).Methods(http.MethodPost)
	router.Handle("/auth/me", JWTMiddleware(http.HandlerFunc(meHandler))).Methods(http.MethodGet)
	router.HandleFunc("/auth/user/new", registerHandler).Methods(http.MethodPost)
	router.Handle("/auth/user/remove", JWTMiddleware(http.HandlerFunc(removeUserHandler))).Methods(http.MethodPost)
}

// meHandler echoes back the JWT claims that JWTMiddleware verified for the
// caller, proving the token was checked and giving callers a cheap way to
// confirm which identity their token resolves to.
func meHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok {
		http.Error(w, "no verified claims on request", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(claims); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// registerHandler creates a new user account from the submitted
// username/password form values, following the same r.FormValue convention
// LoginHandler uses. It validates input, hashes the password, and inserts
// the new row via CreateUser, mapping the result to a status code:
//
//   - 201 on success, with the new user's id/username as JSON.
//   - 400 if the username/password don't meet the credential-shape rules.
//   - 409 if the username is already taken.
//   - 500 for any other (real) database error.
func registerHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	user, err := CreateUser(username, password, nil)
	if err != nil {
		var validationErr *validationInputError
		switch {
		case errors.As(err, &validationErr):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case errors.Is(err, errUsernameTaken):
			http.Error(w, err.Error(), http.StatusConflict)
		default:
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(struct {
		ID       int    `json:"id"`
		Username string `json:"username"`
	}{ID: user.ID, Username: user.Username})
}

// removeUserHandler deletes the account named by the "username" form value.
// It sits behind JWTMiddleware (see AuthRoute), and only lets the verified
// caller delete their own account — comparing the JWT's subject id against
// the target account's id — rather than letting any authenticated caller
// delete an arbitrary username.
//
//   - 400 if username is missing.
//   - 403 if the caller's token doesn't belong to the target account.
//   - 404 if no such user exists.
//   - 200 on success.
//   - 500 for any other (real) database error.
func removeUserHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok {
		http.Error(w, "no verified claims on request", http.StatusInternalServerError)
		return
	}

	username := r.FormValue("username")
	if username == "" {
		http.Error(w, "username is required", http.StatusBadRequest)
		return
	}

	target, err := FindUserByUsername(username)
	if err != nil {
		if errors.Is(err, errQueryNoRows) {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if target.ID != claims.ID {
		http.Error(w, "cannot remove another user's account", http.StatusForbidden)
		return
	}

	if err := RemoveUser(username); err != nil {
		if errors.Is(err, errUserNotFound) {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
