package docs

import (
	"github.com/gorilla/mux"
	httpSwagger "github.com/swaggo/http-swagger"
)

// RegisterSwaggerRoute mounts the generated Swagger UI (backed by the spec
// generated into docs/docs.go, docs/swagger.json and docs/swagger.yaml by
// `swag init`) at /swagger/ on the given router.
func RegisterSwaggerRoute(router *mux.Router) {
	router.PathPrefix("/swagger/").Handler(httpSwagger.WrapHandler)
}
