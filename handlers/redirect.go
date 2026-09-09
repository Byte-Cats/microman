package handlers

import (
	"net/http"
)

func docsPage() string {
	return "/docs"
}

// Redirect godoc
// @Summary Redirect to docs
// @Description Redirects the client from the root path to /docs with a 303 See Other.
// @Tags general
// @Success 303 {string} string "redirect to /docs"
// @Router / [get]
func Redirect(w http.ResponseWriter, r *http.Request) {
	// write message to page
	// redirect to /docs
	http.Redirect(w, r, docsPage(), http.StatusSeeOther)
}
