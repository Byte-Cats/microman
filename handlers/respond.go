package handlers

import "net/http"

// writeString writes s as the body of the response, silently ignoring any
// write error (matching the behavior every stub handler in this package
// used to duplicate individually).
func writeString(w http.ResponseWriter, s string) {
	_, err := w.Write([]byte(s))
	if err != nil {
		return
	}
}
