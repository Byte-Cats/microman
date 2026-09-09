package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/urfave/negroni"
)

// contextKey is a private type used for the request-context key holding
// verified JWT claims, so it can't collide with keys set by other packages.
type contextKey string

const claimsContextKey contextKey = "auth.claims"

// JWTMiddleware wraps next in a negroni chain that verifies the bearer JWT on
// the incoming request before letting it through. Requests with a missing,
// malformed, or invalid/expired token are rejected with 401 and never reach
// next. On success, the verified claims are stashed on the request context
// and retrievable via ClaimsFromContext.
func JWTMiddleware(next http.Handler) http.Handler {
	return negroni.New(
		negroni.HandlerFunc(verifyJWT),
		negroni.Wrap(next),
	)
}

// verifyJWT is the negroni.HandlerFunc that does the actual token check.
func verifyJWT(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	tokenString := extractBearerToken(r)
	if tokenString == "" {
		http.Error(w, "missing authorization token", http.StatusUnauthorized)
		return
	}

	claims, err := VerifyToken(tokenString)
	if err != nil {
		http.Error(w, "invalid or expired token", http.StatusUnauthorized)
		return
	}

	ctx := context.WithValue(r.Context(), claimsContextKey, claims)
	next(w, r.WithContext(ctx))
}

// extractBearerToken pulls the JWT out of the Authorization header, accepting
// both the standard "Bearer <token>" form and a bare token value.
func extractBearerToken(r *http.Request) string {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if header == "" {
		return ""
	}
	if prefix, token, found := strings.Cut(header, " "); found && strings.EqualFold(prefix, "Bearer") {
		return strings.TrimSpace(token)
	}
	return header
}

// ClaimsFromContext returns the JWT claims stashed by JWTMiddleware on the
// request context, if any.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(claimsContextKey).(*Claims)
	return claims, ok
}
