package applogic

// Api is the container for all app properties
type Api struct {
    Settings Settings
    Served   Served
}

// DefaultAPIClient is the default client for the API without config
func DefaultAPIClient() *Api {
    api := new(Api)
    CheckSettings(api)
    InitDefaultRouter(api)
    ServerSetup(api)

    return api
}

func test() *Api {
    api := new(Api)
    CheckSettings(api)
    InitDefaultRouter(api)
    ServerSetup(api)

    return api
}
