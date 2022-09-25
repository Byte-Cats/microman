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
	InitDefaultRouter(api)
	ServerSetup(api)

	return api
}

// RunDefaultClient uses required info from Api and is starting a server
func RunDefaultClient(api *Api) {
	log.Printf("Server is starting on port %v", api.Settings.Port)
	err := http.ListenAndServe(GetRnP(api))
	if err != nil {
		log.Printf("Can't start a server\n\"%v\"", err)
	}
}
