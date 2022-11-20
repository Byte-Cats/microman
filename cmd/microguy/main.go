package main

import (
	"log"

	al "github.com/byte-cats/microman/app"
)

// Init Example startup usage of microman Api
func Init() {
	// Creating a new api instance
	api := al.DefaultAPIClient()

	// Starting the server
	log.Println("Initializing " + al.GetTitle(api) + "...")
	al.RunDefaultClient(api)
}

// main is the entry point for the micro-guy application.
func main() {
	Init()
}
