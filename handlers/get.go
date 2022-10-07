package handlers

import (
	"net/http"
)

func Get(w http.ResponseWriter, r *http.Request) {
	// write message to page

	_, err := w.Write([]byte("Getting something from database"))
	if err != nil {
		return
	}
}
