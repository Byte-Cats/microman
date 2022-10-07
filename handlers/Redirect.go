package handlers

import (
	"net/http"
)

// Redirect to /docs endpoint

// Redirect is a handler for redirecting to a different page
func Redirect(w http.ResponseWriter, r *http.Request) {
	// write message to page

	_, err := w.Write([]byte("Redirecting to another page"))
	if err != nil {
		return
	}
}
