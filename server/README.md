# server

Router setup. `routing.go`'s `InitRouter()` builds the `*mux.Router` (gorilla/mux, `StrictSlash(true)`), and `InitRoutes()` is the single place every route in the app gets registered — general endpoints straight to `handlers.*`, the Swagger UI via `docs.RegisterSwaggerRoute`, and all `/auth/*` routes via `auth.AuthRoute`. Check this file first to see the full API surface. `serving.go`'s `Served`/`ServSetup` (a bare `http.ServeMux`) is currently unused dead weight — not wired into actual request handling.

## Byte Thoughts:

### Notes from Cloud Team
some notes 

### Notes from Backend Team
more notes

### Notes from Dev Ops
technical thinking thoughts be bussin
```
