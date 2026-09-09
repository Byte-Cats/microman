package handlers

import (
	"net/http"
)

// Docs godoc
// @Summary Docs placeholder
// @Description Writes a fixed "Docs" string. Real interactive API docs are served separately by the Swagger UI mounted at /swagger/.
// @Tags general
// @Produce plain
// @Success 200 {string} string "Docs"
// @Router /docs [get]
func Docs(w http.ResponseWriter, r *http.Request) {

	_, err := w.Write([]byte("Docs"))
	if err != nil {
		return
	}
}
