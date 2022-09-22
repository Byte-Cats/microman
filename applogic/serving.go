package applogic

import (
    "net/http"
)

func ServerSetup(api *Api) {
    api.ServeUp = http.NewServeMux()
}
