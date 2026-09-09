package handlers

import (
	"net/http"
)

// Get godoc
// @Summary Get a resource
// @Description Stub handler that is meant to fetch something from the database based on the request; currently just writes a fixed string.
// @Tags rest
// @Produce plain
// @Success 200 {string} string "Getting something from database"
// @Router /get [get]
func Get(w http.ResponseWriter, r *http.Request) {
	writeString(w, "Getting something from database")
}
