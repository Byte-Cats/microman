# auth

Owns all authentication/authorization logic; `handlers`/`server` just mount it (`auth.AuthRoute`) rather than re-implementing anything.

- `constants.go` — shared error-message strings.
- `secrets.go` — `FindSecret` reads the signing secret (and its expiration) from env vars.
- `crypto.go` — AES-GCM `Encrypt`/`Decrypt` helpers, keyed off the secret above.
- `rules.go` — `UserCredentialRules`/`validateUserInput` and friends: username/password shape validation.
- `users.go` — the `User` model, `FindUserByUsername`, `CreateUser` (validates input, rejects a taken username, hashes the password, inserts the row), and `RemoveUser` (deletes by username). All three go through `database.go`'s `getDB()`.
- `database.go` — `ConnectDB`/`CloseDB`, a raw MySQL `database/sql` connection (separate from `data.Connect`, which goes through datastation). The package-level `*sql.DB` is lazily opened by `getDB()` behind a `sync.Once`, so every DB-touching function in the package calls `getDB()` rather than reading the package var directly — nothing calls this at startup otherwise, and the old unused `initDB()` meant the connection was never actually established.
- `schema.sql` — `CREATE TABLE IF NOT EXISTS users (...)` matching the exact column set `FindUserByUsername` selects and `CreateUser` inserts.
- `jwt.go` — `generateJWT`/`VerifyToken`, built on `golang-jwt/jwt/v5`.
- `middleware.go` — `JWTMiddleware`, a negroni-based `http.Handler` wrapper that verifies the bearer token via `VerifyToken` and either lets the request through (claims attached to the request context, retrievable via `ClaimsFromContext`) or returns 401.
- `login.go` — `LoginHandler`: validates credentials, checks the password hash, and issues a JWT on success.
- `password.go` — `hashAndSaltPassword`, the bcrypt hashing helper.
- `route.go` — `AuthRoute(router *mux.Router)`, the single entry point that mounts every `/auth/*` route: `POST /auth/login` (public), `GET /auth/me` (JWT-protected, echoes verified claims), `POST /auth/user/new` (public, creates a user via `CreateUser` — 201/400/409/500), and `POST /auth/user/remove` (JWT-protected; the caller may only remove the account their own token belongs to — 200/400/403/404/500).

## Byte Thoughts:

### Notes from Cloud Team
some notes 

### Notes from Backend Team
more notes

### Notes from Dev Ops
technical thinking thoughts be bussin
```
