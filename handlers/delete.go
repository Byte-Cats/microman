package handlers

import (
	"net/http"
)

// Deleter godoc
// @Summary Delete a resource
// @Description Stub handler that is meant to delete something from the database; currently just writes a fixed string. The route is registered without a method restriction, so it currently responds to any HTTP method.
// @Tags rest
// @Produce plain
// @Success 200 {string} string "Something is going to be deleted"
// @Router /delete [delete]
func Deleter(w http.ResponseWriter, r *http.Request) {
	_, err := w.Write([]byte("Something is going to be deleted"))
	if err != nil {
		return
	}
}
