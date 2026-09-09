package handlers

import (
	"net/http"
)

// Deleter handler that deletes something from the database
func Deleter(w http.ResponseWriter, r *http.Request) {
	writeString(w, "Something is going to be deleted")
}
