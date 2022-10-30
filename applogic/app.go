package applogic

import "github.com/byte-cats/microman/server"

// Api is the container for all app properties
type Api struct {
	Settings Settings
	Served   server.Served
}

// DefaultAPIClient is the default client for the API without config
func DefaultAPIClient() *Api {
	api := new(Api)
	CheckSettings(api)

	//server.InitDefaultRouter(api)
	server.ServSetup(api)

	return api
}
