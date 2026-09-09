# handlers

One file per route: `home.go`, `info.go`, `redirect.go`, `docs.go`, `health.go` (general endpoints), and `add.go`/`get.go`/`edit.go`/`delete.go` (CRUD stubs — mostly still placeholder responses, not real database-backed logic). `respond.go` holds `writeString`, a small shared helper used by every handler here to write a response body and swallow the write error consistently, instead of each handler repeating that boilerplate. Each handler also carries `swaggo`-style doc comments (`@Summary`, `@Router`, ...) that feed the generated docs in `docs/`. Auth-specific routes live in the `auth` package instead (see `auth.AuthRoute`), not here.

## Byte Thoughts:

### Notes from Cloud Team
some notes 

### Notes from Backend Team
more notes

### Notes from Dev Ops
technical thinking thoughts be bussin
```
