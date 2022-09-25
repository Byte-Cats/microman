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
func GetRouter(api *Api) *mux.Router {
	return api.Served.Router
}
