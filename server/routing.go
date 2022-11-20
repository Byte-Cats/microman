package server

import (
	"github.com/byte-cats/microman/handlers"
	"github.com/gorilla/mux"
)

// InitRouter initializes the router for the api client
func InitRouter() *mux.Router {
	router := mux.NewRouter().StrictSlash(true)
	return router
}

// InitRoutes setup all handlers routing
func InitRoutes(router *mux.Router) {
	// General Api endpoints
	router.HandleFunc("/", handlers.Redirect)
	router.HandleFunc("/home", handlers.Home)
	router.HandleFunc("/docs", handlers.Docs)
	router.HandleFunc("/info", handlers.InfoDealer)
	// Auth endpoints
	router.HandleFunc("/auth/login", handlers.Get)
	router.HandleFunc("/auth/user/new", handlers.Get)
	router.HandleFunc("auth/user/remove", handlers.Get)

	// Rest endpoints
	router.HandleFunc("/get", handlers.Get)
	router.HandleFunc("/add", handlers.Adder)
	router.HandleFunc("/edit", handlers.Editor)
	router.HandleFunc("/delete", handlers.Deleter)
}
