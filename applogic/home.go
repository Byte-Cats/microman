package applogic

import (
    "net/http"
)

// HomeHandler for the home page
func HomeHandler(w http.ResponseWriter, r *http.Request) {
    _, err := w.Write([]byte("This is the home page"))
    if err != nil {
        return
    }
}
