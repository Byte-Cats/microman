package main

import (
	al "github.com/byte-cats/microman/applogic"
	"log"

	"github.com/byte-cats/microman/server"
)

// main is the entry point for the microguy application.
func main() {
	// Creating a new api instance
	api := al.DefaultAPIClient()

	// Starting the server
	log.Println("Initializing " + al.GetTitle(api) + "...")
	server.RunDefaultClient(api)
}
