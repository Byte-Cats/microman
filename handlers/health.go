package handlers

import (
	"net/http"
)

// Health is a simple healthcheck endpoint that reports the service is up
func Health(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte("ok"))
	if err != nil {
		return
	}
}
