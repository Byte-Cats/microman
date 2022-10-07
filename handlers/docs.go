package handlers

import (
	"net/http"
)

// Docs http handler for swag docs
func Docs(w http.ResponseWriter, r *http.Request) {
	// write message to page

	_, err := w.Write([]byte("Docs"))
	if err != nil {
		return
	}
}
