package handlers

import (
	"fmt"
	"net/http"

	"github.com/byte-cats/microman/applogic"
)

// HomeSecrets the secrets of the home page to be displayed
func HomeSecrets() string {
	return "\tWelcome to the home sweet home!!!\nThis beautiful microservice app keeps growing with the \"Byte Cats\" company!\nAnd you can be one of us! It depends on you and your desire to be a cool programmer!"
}

// Home there's no place like it apparently
func Home(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
	_, err := fmt.Fprintf(w, HomeSecrets())
	if err != nil {
		return
	}
	applogic.Log("Handling a request with method \"%v\" on a url = \"%v\"", r.Method, r.RequestURI)
}
