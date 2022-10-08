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

func SecureEndpoint(path string, middleware *jwtMiddleware.JWTMiddleware, handler http.HandlerFunc, router *mux.Router) {
	router.Handle(path, negroni.New(
		negroni.HandlerFunc(middleware.HandlerWithNext),
		negroni.Wrap(http.HandlerFunc(handler)),
	))
}

func getSecret() []byte {
	secret := os.Getenv("SECRET")
	if secret == "" {
		panic("Error: Must provide a secret key under env variable SECRET")
	}

	secretbite, err := hex.DecodeString(secret)

	if err != nil {
		// probably malformed secret, panic out
		panic(err)
	}

	return secretbite
}
