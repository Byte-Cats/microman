package main

import (
	"log"

	"microbro/applogic"
)

func main() {
	api := applogic.DefaultAPIClient()
	log.Println("Initializing " + applogic.GetTitle(api) + "...")
	applogic.RunDefaultClient(api)
}
