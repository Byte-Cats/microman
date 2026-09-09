package handlers

import (
	"net/http"
)

// Editor godoc
// @Summary Edit a resource
// @Description Stub handler that is meant to edit something in the database; currently just writes a fixed string. The route is registered without a method restriction, so it currently responds to any HTTP method.
// @Tags rest
// @Produce plain
// @Success 200 {string} string "Something is going to be edited"
// @Router /edit [put]
func Editor(w http.ResponseWriter, r *http.Request) {
	_, err := w.Write([]byte("Something is going to be edited"))
	if err != nil {
		return
	}
}
