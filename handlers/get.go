package handlers

import (
	"net/http"
)

// Get handler that gets something from the database according to the request received from the client in json
func Get(w http.ResponseWriter, r *http.Request) {

	_, err := w.Write([]byte("Getting something from database"))
	if err != nil {
		return
	}
}
