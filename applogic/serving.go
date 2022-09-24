package applogic

import (
	"net/http"
)

// Creating a newServeMux to pass it in api struct and
// create a mux.router afterwards
func ServerSetup(api *Api) *http.ServeMux {
	api.ServeUp = http.NewServeMux()
	return api.ServeUp
}
