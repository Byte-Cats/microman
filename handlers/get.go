package handlers

import (
	"net/http"
)

func Get(w http.ResponseWriter, r *http.Request) {

	_, err := w.Write([]byte("Getting something from database"))
	if err != nil {
		return
	}
}
