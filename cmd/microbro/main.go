package main

import (
    "fmt"
    "os"

    "microbro/applogic"
)

func main() {

    fmt.Println("Initializing microbro Api")

    // Grab API_PORT from environment variables
    // If not set, use default port 8080
    apiPort := os.Getenv("API_PORT")
    if apiPort == "" {
        apiPort = "8080"
    }
    api := applogic.DefaultAPIClient()
    fmt.Println("Micro bro is running on \n" + api.BaseUrl + ":" + api.Port)
    applogic.RunDefaultClient(api, apiPort)

}
