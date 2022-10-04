package applogic

import (
	"microbro/handlers"

	"github.com/gorilla/mux"
)

// InitRouter initializes the router for the api client
func InitRouter(api *Api) *mux.Router {
	api.Served.Router = mux.NewRouter().StrictSlash(true)
	return api.Served.Router
}

// InitRoutes setup all handlers routing
func InitRoutes(api *Api) {
	router := api.Served.Router
	router.HandleFunc("/", handlers.Home)
	router.HandleFunc("/docs", handlers.Docs)
	router.HandleFunc("/info", handlers.InfoDealer)
	router.HandleFunc("/add", handlers.Adder)
	router.HandleFunc("/delete", handlers.Deleter)
	router.HandleFunc("/edit", handlers.Editor)
}

// InitDefaultRouter for api instance
func InitDefaultRouter(api *Api) {
	InitRouter(api)
	InitRoutes(api)
}

// GetRouter returns the router of the api instance
func GetRouter(api *Api) *mux.Router {
	return api.Served.Router
}
final test	
