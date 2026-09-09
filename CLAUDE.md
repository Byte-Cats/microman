# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`microman` (module `github.com/byte-cats/microman`) is a minimal Go HTTP API starter kit built without a web framework — just `net/http`, `gorilla/mux` for routing, and `urfave/negroni` for middleware. It's a scaffold/example project ("Minimal Go Api Starter Kit"), not a production service — expect unfinished stubs and placeholder handlers throughout.

## Commands

- Build the actual entrypoint (matches what CI runs): `go build ./cmd/microguy/main.go`
- Build everything: `go build ./...`
- Vet: `go vet ./...`
- Format check: `gofmt -l .` (exclude `vendor/`)
- Tidy modules: `go mod tidy`
- There is a `vendor/` directory — if it's still present, keep it in sync with `go mod vendor` after any dependency change, since Go will build with `-mod=vendor` automatically whenever `vendor/modules.txt` exists.
- No `_test.go` files exist yet (this is open issue #26 — "test driven go development"). Once tests exist, run a single one with `go test ./<package> -run TestName -v`.
- There is no Makefile, despite `Jenkinsfile` invoking `make unit-tests` / `make functional-tests` and `deploy/build.sh` assuming a `make`-based flow — those CI/build scripts are stale relative to the actual repo layout. Don't assume they work as-is.
- `deploy/build.sh` and the `Dockerfile` both build from `cmd/microbro/`, but the real (only) command package is `cmd/microguy/` — another stale-path leftover from a rename. Follow `.github/workflows/go.yml` (which builds `cmd/microguy`) as the source of truth for what actually builds.

## Architecture

Call chain: `cmd/microguy/main.go` → `app` package → `server` package → `handlers` package, with `auth`, `data`, and `log` as supporting packages.

- **`app/`** — `Api` struct is the top-level container: holds `Settings` (title/hostname/port/version, populated from env vars with defaults via `app.CheckSettings`) and `server.Served` (the router + a raw `http.ServeMux`, unused). `app.DefaultAPIClient()` builds the default instance; `app.RunDefaultClient()` calls `http.ListenAndServe`. Getter/setter functions here (`GetTitle`, `SetPort`, etc.) are the pattern used throughout instead of exported struct fields being accessed directly.
- **`server/`** — `InitRouter()` creates the `*mux.Router`; `InitRoutes()` registers every endpoint path to its handler in one place (this is the map of the whole API surface — check it first to see what routes exist). `serving.go`'s `Served`/`ServSetup` (a plain `http.ServeMux`) is currently dead weight, not wired into actual request handling.
- **`handlers/`** — one file per route/verb (`add.go`, `get.go`, `edit.go`, `delete.go`, `home.go`, `info.go`, `redirect.go`, `docs.go`, `auth.go`). Most are still stub handlers that just write a fixed string; `auth.go` is an empty placeholder (comment-only) despite `/auth/login`, `/auth/user/new`, `/auth/user/remove` already being routed to `handlers.Get` in `server/routing.go`.
- **`auth/`** — self-contained package for credential rules (`rules.go`), JWT issuing/verification (`jwt.go`), AES encrypt/decrypt (`crypto.go`), DB access (`database.go`, MySQL via `database/sql`), secrets loaded from env (`secrets.go`), and a `User` model (`users.go`). Several functions across `login.go`/`jwt.go`/`users.go` call helpers that are declared but never defined elsewhere in the package (e.g. `getUserFromDBByUsername`, `comparePasswordHash`, `validateInput`, `ValidateUserCredentials`, `generateJWTToken`) — this package does not fully compile/link end-to-end as written; check what actually exists before assuming a function is callable.
- **`data/`** — meant to hold the database layer; currently near-empty placeholders (`connection.go`, `data.go` are just package comments). `json.go` has the one real helper, `JsonConvert`, wrapping `encoding/json`. The README says the project is meant to integrate a separate library, [`byte-cats/datastation`](https://github.com/byte-cats/datastation), here — that integration hasn't happened yet (see issue #17).
- **`log/`** — custom logger (`log.Log`), unrelated to the stdlib `log` package also used directly in a few handlers (some files import both under an alias, e.g. `log2`).
- **`docs/`** — intended location for Swagger/OpenAPI generation; `swag.go` and `swag.yaml` are currently placeholders (issue #37).

## Known repo-wide gotchas

- Module path is lowercase (`github.com/byte-cats/microman`) while the GitHub org/repo is `Byte-Cats/microman` — this matters for import paths vs. browser URLs.
- Several packages (`auth`, `cmd/microguy`) reference undefined identifiers or wrong import aliases and don't currently build cleanly — don't assume `go build ./...` succeeds without checking first.
- go.mod dependencies were pinned to very old versions (jwt-go from a since-archived fork, x/crypto from 2019); if you're touching `auth/` or dependency versions, check `go.mod` for what's currently pinned rather than assuming recent versions.
