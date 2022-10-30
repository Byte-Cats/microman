package server

import (
	al "github.com/byte-cats/microman/applogic"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

// Served is a struct that holds server and router
type Served struct {
	Router  *mux.Router
	ServeUp *http.ServeMux
}

// ServSetup is a function that sets up the web server
func ServSetup(api *al.Api) *http.ServeMux {
	// Creating a newServeMux to pass it in api struct and
	api.Served.ServeUp = http.NewServeMux()
	// return it to be used in main (maybe)
	return api.Served.ServeUp
}

// RunDefaultClient is a function that serves the Api on the default port
func RunDefaultClient(api *al.Api) {
	log.Printf("Server is starting on port %v", api.Settings.Port)
	err := http.ListenAndServe(al.GetRnP(api))
	if err != nil {
		log.Printf("Can't start a server\n\"%v\"", err)
	}
}
