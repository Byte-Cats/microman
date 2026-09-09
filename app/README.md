# app

Top-level container for the running API instance. `app.go` defines the `Api` struct (holds `Settings` plus the `server.Served` router/mux pair), `DefaultAPIClient()` to build one with env-derived settings, and `RunDefaultClient()` to actually call `http.ListenAndServe`. `settings.go` holds `Settings` (title, hostname, port, version) and the `Check*`/`Get*`/`Set*`/`Show*` getter-setter functions used to populate it from environment variables with hardcoded defaults as fallback.

## Byte Thoughts:

### Notes from Cloud Team
some notes 

### Notes from Backend Team
more notes

### Notes from Dev Ops
technical thinking thoughts be bussin
```
