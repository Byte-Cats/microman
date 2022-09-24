package applogic

import (
	"microbro/handlers"

	"github.com/gorilla/mux"
)

// InitRouter initializes the router for the api client
func InitRouter(api *Api) *mux.Router {
	api.Router = mux.NewRouter().StrictSlash(true)
	return api.Router
}

// InitRoutes setup all handlers routing
func InitRoutes(api *Api) {
	router := api.Router
	router.HandleFunc("/", handlers.Home)
	router.HandleFunc("/info", handlers.InfoDealer)
	//http.HandleFunc("/add", AddHandler)
	//http.HandleFunc("/delete", DeleteHandler)
	//http.HandleFunc("/edit", EditHandler)
}

// InitDefaultRouter for api instance
func InitDefaultRouter(api *Api) {
	InitRouter(api)
	InitRoutes(api)
}
