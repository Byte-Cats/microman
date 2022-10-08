package handlers

import (
	"net/http"
)

// Adder handler that adds something to the database
func Adder(w http.ResponseWriter, r *http.Request) {

	_, err := w.Write([]byte("Something is going to be added"))
	if err != nil {
		return
	}

}
