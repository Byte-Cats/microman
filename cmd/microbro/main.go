package main

import (
	"log"

	"microbro/applogic"
)

func main() {

	log.Println("Initializing microbro Api")

	api := applogic.DefaultAPIClient()
	// Grab API_PORT from environment variables
	// If not set, use default port 9090
	// apiPort := os.Getenv("API_PORT")
	// if apiPort == "" {
	// 	apiPort = ":9090"
	// }
	apiPort := ":9090"
	applogic.RunDefaultClient(api, apiPort)

}
