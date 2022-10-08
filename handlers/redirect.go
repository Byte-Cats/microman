package handlers

import (
	"net/http"
)

func docsPage() string {
	return "/docs"
}

// Redirect is a handler for redirecting to a different page
func Redirect(w http.ResponseWriter, r *http.Request) {
	// write message to page
	// redirect to /docs
	http.Redirect(w, r, docsPage(), http.StatusSeeOther)
}
