package applogic

import (
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
	router.HandleFunc("/", HomeLander)
	router.HandleFunc("/info", InfoHandler)
	//http.HandleFunc("/add", AddHandler)
	//http.HandleFunc("/delete", DeleteHandler)
	//http.HandleFunc("/edit", EditHandler)
}

// InitDefaultRouter for api instance
func InitDefaultRouter(api *Api) {
	InitRouter(api)
	InitRoutes(api)
}
