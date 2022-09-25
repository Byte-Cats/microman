package applogic

import (
	"log"
	"net/http"
)

// Api is the container for all app properties
type Api struct {
	Settings Settings
	Served   Served
}

// DefaultAPIClient is the default client for the API without config
func DefaultAPIClient() *Api {
	api := new(Api)
	CheckSettings(api)
	//api.Settings.Title = "Name of the app"
	//api.Settings.Version = "0.3.0"
	//api.Settings.Hostname = "http://localhost"
	//api.Settings.Port = ":9090"

	InitDefaultRouter(api)
	ServerSetup(api)

	return api
}

// RunDefaultClient uses required info from Api and is starting a server
func RunDefaultClient(api *Api) {
	log.Printf("Server is starting on port %v", api.Settings.Port)
	err := http.ListenAndServe(api.Settings.Port, api.Served.Router)
	if err != nil {
		log.Printf("Can't start a server\n\"%v\"", err)
	}
}
