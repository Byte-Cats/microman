package handlers

import (
	log2 "github.com/byte-cats/microman/log"
	"log"
	"net/http"
)

// Informant for info endpoint page output
func Informant() string {
	return "This is the info function"
}

// InfoDealer string to http response
func InfoDealer(w http.ResponseWriter, r *http.Request) {
	log.Printf("Handling a request with a method \"%v\" and url \"%v\"", r.Method, r.URL.Path)
	_, err := w.Write([]byte(Informant()))
	if err != nil {
		log2.Log("%v", err)
	}
}
