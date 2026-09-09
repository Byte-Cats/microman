package handlers

import (
	"net/http"
)

// Get handler that gets something from the database according to the request received from the client in json
func Get(w http.ResponseWriter, r *http.Request) {
	writeString(w, "Getting something from database")
}
