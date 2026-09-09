package handlers

import (
	"net/http"
)

// Docs http handler for swag docs
func Docs(w http.ResponseWriter, r *http.Request) {
	writeString(w, "Docs")
}
