package main

import (
	"log"

	"microbro/applogic"
)

func main() {
	log.Println("Initializing micro bruh Api")
	api := applogic.DefaultAPIClient()
	applogic.RunDefaultClient(api)
}
