package applogic

import (
    "github.com/gorilla/mux"
)

// InitRouter initializes the router for the api client
func InitRouter(api *Api) {
    api.Router = mux.NewRouter().StrictSlash(true)
    InitRoutes(api)
}

// InitRoutes setup all routing
func InitRoutes(api *Api) {
    router := api.Router
    router.HandleFunc("/", HomeHandler)
    router.HandleFunc("/info", InfoHandler)
    api.Router = router
    //http.HandleFunc("/add", AddHandler)
    //http.HandleFunc("/delete", DeleteHandler)
    //http.HandleFunc("/edit", EditHandler)
}

// InitDefaultRouter for api instance
func InitDefaultRouter(api *Api) {
    InitRouter(api)
    InitRoutes(api)
}
