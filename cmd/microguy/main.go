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

// main is the entry point for the micro-guy application.
func main() {
	Init()
}
