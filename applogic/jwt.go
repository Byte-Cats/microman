package applogic

import (
	"net/http"

	jwtMiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/form3tech-oss/jwt-go"
	_ "github.com/form3tech-oss/jwt-go"
	"github.com/gorilla/mux"
	"github.com/urfave/negroni"
)

func InitMiddleware(secret string) *jwtMiddleware.JWTMiddleware {
	middleware := jwtMiddleware.New(jwtMiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			return []byte(secret), nil
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
