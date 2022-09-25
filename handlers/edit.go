package handlers

import (
	"net/http"
)

// Editor is a handler for editing something in a database
func Editor(w http.ResponseWriter, r *http.Request) {
	_, err := w.Write([]byte("Something is going to be edited"))
	if err != nil {
		return
	}
}
