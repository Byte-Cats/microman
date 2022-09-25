package applogic

import (
	"net/http"

	"github.com/gorilla/mux"
)

// Served is a struct that holds server and router
type Served struct {
	Router  *mux.Router
	ServeUp *http.ServeMux
}

// ServerSetup is a function that sets up the web server
func ServerSetup(api *Api) *http.ServeMux {
	// Creating a newServeMux to pass it in api struct and
	api.Served.ServeUp = http.NewServeMux()
	// return it to be used in main (maybe)
	return api.Served.ServeUp
}
