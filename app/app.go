package app

import (
	"log"
	"net/http"

	"github.com/byte-cats/microman/server"
	"github.com/gorilla/mux"
)

// Api is the container for all app properties
type Api struct {
	Settings Settings
	Served   server.Served
}

// DefaultAPIClient is the default client for the API without config
func DefaultAPIClient() *Api {
	api := new(Api)
	CheckSettings(api)

	// server.InitDefaultRouter(api)
	api.Served.ServeUp = server.ServSetup()

	return api
}

// InitDefaultRouter for api instance
func InitDefaultRouter(api *Api) {
	api.Served.Router = server.InitRouter()
	server.InitRoutes(api.Served.Router)
}

// GetRouter returns the router of the api instance
func GetRouter(api *Api) *mux.Router {
	return api.Served.Router
}

// RunDefaultClient is a function that serves the Api on the default port
func RunDefaultClient(api *Api) {
	log.Printf("Server is starting on port %v", api.Settings.Port)
	err := http.ListenAndServe(GetRnP(api))
	if err != nil {
		log.Printf("Can't start a server\n\"%v\"", err)
	}
}
