# auth

Owns all authentication/authorization logic; `handlers`/`server` just mount it (`auth.AuthRoute`) rather than re-implementing anything.

- `constants.go` — shared error-message strings.
- `secrets.go` — `FindSecret` reads the signing secret (and its expiration) from env vars.
- `crypto.go` — AES-GCM `Encrypt`/`Decrypt` helpers, keyed off the secret above.
- `rules.go` — `UserCredentialRules`/`validateUserInput` and friends: username/password shape validation.
- `users.go` — the `User` model and `FindUserByUsername`.
- `database.go` — `ConnectDB`/`CloseDB`, a raw MySQL `database/sql` connection (separate from `data.Connect`, which goes through datastation).
- `jwt.go` — `generateJWT`/`VerifyToken`, built on `golang-jwt/jwt/v5`.
- `middleware.go` — `JWTMiddleware`, a negroni-based `http.Handler` wrapper that verifies the bearer token via `VerifyToken` and either lets the request through (claims attached to the request context, retrievable via `ClaimsFromContext`) or returns 401.
- `login.go` — `LoginHandler`: validates credentials, checks the password hash, and issues a JWT on success.
- `password.go` — `hashAndSaltPassword`, the bcrypt hashing helper.
- `route.go` — `AuthRoute(router *mux.Router)`, the single entry point that mounts every `/auth/*` route: `POST /auth/login` (public), `GET /auth/me` (JWT-protected, echoes verified claims — the live demonstration that the middleware actually gates a route), and `POST /auth/user/new` / `POST /auth/user/remove` (honest `501 Not Implemented` stubs, since there's no backing create/remove-user logic yet).

## Byte Thoughts:

### Notes from Cloud Team
some notes 

### Notes from Backend Team
more notes

### Notes from Dev Ops
technical thinking thoughts be bussin
```
