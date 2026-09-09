package handlers

import (
	"fmt"
	"github.com/byte-cats/microman/log"
	"net/http"
)

// HomeSecrets the secrets of the home page to be displayed
func HomeSecrets() string {
	return "\tWelcome to the home sweet home!!!\nThis beautiful microservice app keeps growing with the \"Byte Cats\" company!\nAnd you can be one of us! It depends on you and your desire to be a cool programmer!"
}

// Home godoc
// @Summary Home page
// @Description Writes a fixed welcome message for the microman API and logs the request.
// @Tags general
// @Produce plain
// @Success 200 {string} string "welcome message"
// @Router /home [get]
func Home(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
	_, err := fmt.Fprint(w, HomeSecrets())
	if err != nil {
		return
	}
	log.Log("Handling a request with method \"%v\" on a url = \"%v\"", r.Method, r.RequestURI)
}
