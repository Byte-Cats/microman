package applogic

import (
    "net/http"
)

// Info returns string
func Info() string {
    return "This is the info function"
}

// InfoHandler string to http response
func InfoHandler(w http.ResponseWriter, r *http.Request) {
    _, err := w.Write([]byte(Info()))
    if err != nil {
        return
    }
}
