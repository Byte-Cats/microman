package applogic

import (
	"log"
	"net/http"
)

// Info page output
func Info() string {
	return "This is the info function"
}

// InfoHandler string to http response
func InfoHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Handling a request with a method \"%v\" and url \"%v\"", r.Method, r.URL.Path)
	_, err := w.Write([]byte(Info()))
	if err != nil {
		log.Println(err)
	}
}
