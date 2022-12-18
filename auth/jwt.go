package auth

import (
	"encoding/hex"
	"net/http"
	"os"

	jwtMiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/form3tech-oss/jwt-go"
	"github.com/gorilla/mux"
	"github.com/urfave/negroni"
)

// InitMiddleware initializes a jwtMiddleware.JWTMiddleware instance with the given secret key.
// This middleware can be used to secure an HTTP endpoint by passing it to the SecureEndpoint function.
func InitMiddleware(secret []byte) *jwtMiddleware.JWTMiddleware {
	middleware := jwtMiddleware.New(jwtMiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			return secret, nil
		},
		SigningMethod: jwt.SigningMethodHS256,
		Extractor:     jwtMiddleware.FromFirst(jwtMiddleware.FromAuthHeader),
	})
	return middleware
}

// SecureEndpoint secures an HTTP endpoint with the given middleware.
// When a request is made to this endpoint, the middleware will check for a valid JWT in the request header
// and call the handler function if the JWT is valid.
// If the JWT is invalid or not present, the middleware will return an error to the client.
func SecureEndpoint(path string, middleware *jwtMiddleware.JWTMiddleware, handler http.HandlerFunc, router *mux.Router) {
	router.Handle(path, negroni.New(
		negroni.HandlerFunc(middleware.HandlerWithNext),
		negroni.Wrap(http.HandlerFunc(handler)),
	))
}

// FindSecret retrieves the secret key from the SECRET environment variable.
// If the SECRET environment variable is not set, the function will panic.
func FindSecret() []byte {
	secret := os.Getenv("SECRET")
	if secret == "" {
		panic("Error: Must provide a secret key under env variable SECRET")
	}

	secretBits, err := hex.DecodeString(secret)

	if err != nil {
		// probably malformed secret, panic out
		panic(err)
	}

	return secretBits
}
