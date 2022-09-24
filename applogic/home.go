package applogic

import (
	"fmt"
	"log"
	"net/http"
)

// Home page output
func Home() string {
	return "\tWelcome to the home sweet home!!!\nThis beautiful microservice app keeps growing with the \"Byte Cats\" company!\nAnd you can be one of us! It depends on you and your desire to be a cool programmer!"
}

// HomeHandler for the home page
func HomeHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
	fmt.Fprintf(w, Home())
	log.Printf("Handling a request with method \"%v\" on a url = \"%v\"", r.Method, r.RequestURI)
}
