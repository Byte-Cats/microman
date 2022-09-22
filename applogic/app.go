package applogic

import (
    "net/http"

    "github.com/gorilla/mux"
)

// Api is the container for all app properties
type Api struct {
    Title   string
    Version string
    BaseUrl string
    Port    string
    Router  *mux.Router
    ServeUp *http.ServeMux
}

// DefaultAPIClient is the default client for the API without config
func DefaultAPIClient() *Api {
    api := new(Api)
    api.Title = "My API"
    api.Version = "1.0.0"
    api.BaseUrl = "http://localhost"
    api.Port = "8080"
    InitDefaultRouter(api)
    ServerSetup(api)

    return api
}

func RunDefaultClient(api *Api, port string) {
    port = ":" + port
    err := http.ListenAndServe(port, api.ServeUp)
    if err != nil {
        return
    }
}
