package server

import (
	"net/http"

	"github.com/gorilla/mux"
)

// Served is a struct that holds server and router
type Served struct {
	Router  *mux.Router
	ServeUp *http.ServeMux
}

// ServSetup is a function that sets up the web server
func ServSetup() *http.ServeMux {

	// return it to be used in main (maybe)
	return http.NewServeMux()
}
