package applogic

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

// Api is the container for all app properties
type Api struct {
	Title   string
	Version string
	BaseUrl string
	Port    string
	Router  *mux.Router
	ServeUp *http.ServeMux
}

// DefaultAPIClient is the default client for the API without config
func DefaultAPIClient() *Api {
	api := new(Api)
	api.Title = "My API"
	api.Version = "1.0.0"
	api.BaseUrl = "http://localhost"
	api.Port = ":9090"
	InitDefaultRouter(api)
	ServerSetup(api)

	return api
}

// The main part of app that takes needed info from Api config and is starting a server
func RunDefaultClient(api *Api, port string) {
	log.Printf("Server is starting on port %v", port)
	err := http.ListenAndServe(port, api.Router)
	if err != nil {
		log.Printf("Can't start a server\n\"%v\"", err)
	}
}
