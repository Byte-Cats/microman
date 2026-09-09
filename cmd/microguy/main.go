package main

import (
	"log"

	app "github.com/byte-cats/microman/app"
)

// Init Example startup usage of microman Api
func Init() {
	// Creating a new api instance
	api := app.DefaultAPIClient()

	// Starting the server
	log.Println("Initializing " + app.GetTitle(api) + "...")
	app.RunDefaultClient(api)
}

// @title Microman API
// @version 0.420.69
// @description Minimal Go HTTP API starter kit (no web framework) built on net/http and gorilla/mux. Most routes are still stub handlers; see the /docs endpoint and each handler's doc comment for the actual current behavior.
// @termsOfService http://swagger.io/terms/

// @contact.name Byte Cats
// @contact.url https://github.com/Byte-Cats/microman

// @license.name MIT
// @license.url https://github.com/Byte-Cats/microman/blob/main/LICENCE

// @host localhost:6969
// @BasePath /

// main is the entry point for the micro-guy application.
func main() {
	Init()
}
