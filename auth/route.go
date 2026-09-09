package auth

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
)

// AuthRoute mounts the auth package's routes and middleware onto router.
//
//   - POST /auth/login       public, exchanges valid credentials for a JWT.
//   - GET  /auth/me          protected by JWTMiddleware, echoes the caller's
//     verified claims back as JSON; this is the demonstration of the JWT
//     middleware actually gating a route end-to-end.
//   - POST /auth/user/new    stubbed: there is no CreateUser backing this
//     yet, so it honestly reports 501 rather than pretending to work.
//   - POST /auth/user/remove stubbed for the same reason.
func AuthRoute(router *mux.Router) {
	router.HandleFunc("/auth/login", LoginHandler).Methods(http.MethodPost)
	router.Handle("/auth/me", JWTMiddleware(http.HandlerFunc(meHandler))).Methods(http.MethodGet)
	router.HandleFunc("/auth/user/new", registerHandler).Methods(http.MethodPost)
	router.HandleFunc("/auth/user/remove", removeUserHandler).Methods(http.MethodPost)
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

// registerHandler would create a new user account. There is no CreateUser
// (or equivalent) backing store implemented anywhere in this package yet, so
// rather than faking success this honestly reports that the feature isn't
// built out.
func registerHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "user registration is not implemented yet", http.StatusNotImplemented)
}

// removeUserHandler would delete a user account. Same situation as
// registerHandler: no backing logic exists yet, so it reports 501 instead of
// silently succeeding.
func removeUserHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "user removal is not implemented yet", http.StatusNotImplemented)
}
