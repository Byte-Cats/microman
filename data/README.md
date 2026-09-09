# data

The database/data layer. `connection.go` opens (and closes) the app's MySQL connection through [`byte-cats/datastation`](https://github.com/byte-cats/datastation) — `Connect()` reads `DATABASE_TYPE`/`DATABASE_HOST`/`DATABASE_PORT`/`DATABASE_NAME`/`DATABASE_USER`/`DATABASE_PASSWORD` env vars via datastation's config helpers and returns a ready `*sql.DB`. `json.go` has `JsonConvert`, a `jsoniter`-backed (drop-in `encoding/json` replacement, for speed) marshal helper used by a couple of handlers. `data.go` is currently just a placeholder for future data structures.

## Byte Thoughts:

### Notes from Cloud Team
some notes 

### Notes from Backend Team
more notes

### Notes from Dev Ops
technical thinking thoughts be bussin
```
