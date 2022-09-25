package handlers

import (
	"net/http"
)

// Deleter handler that deletes something from the database
func Deleter(w http.ResponseWriter, r *http.Request) {
	_, err := w.Write([]byte("Something is going to be deleted"))
	if err != nil {
		return
	}
}
