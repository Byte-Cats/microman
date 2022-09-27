package main

import (
	"log"

	"microman/applogic"
)

func main() {
	// Creating a new api instance
	api := applogic.DefaultAPIClient()
	// Starting the server
	log.Println("Initializing " + applogic.GetTitle(api) + "...")
	applogic.RunDefaultClient(api)
}
