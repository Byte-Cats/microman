package applogic

import (
	"net/http"

	"github.com/gorilla/mux"
)

type Served struct {
	Router  *mux.Router
	ServeUp *http.ServeMux
}

// Creating a newServeMux to pass it in api struct and
// create a mux.router afterwards
func ServerSetup(api *Api) *http.ServeMux {
	api.Served.ServeUp = http.NewServeMux()
	return api.Served.ServeUp
}
