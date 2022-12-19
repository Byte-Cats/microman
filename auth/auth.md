# Auth System

This auth system is designed to provide secure user registration and login functionality, using bcrypt to hash and salt passwords and JWT tokens to authenticate users. It also includes validation checks to ensure that user input meets certain criteria, and a database connection to store and retrieve user records. With this system in place, you can confidently manage user access to your application and keep your users' data safe and secure.

### Features
- User registration: The `handleCreateUser` function processes requests to create new users, by validating the provided username and password, checking to see if the username is already in use, hashing and salting the password, and creating a new user record in the database.
- User login: The `handleUserLogin` function processes login requests, by validating the provided username and password and retrieving the corresponding user record from the database. If the login is successful, it generates a JWT token for the user.
- Password hashing and salting: The `hashAndSaltPassword` function hashes and salts the given password using bcrypt.
- JWT token generation: The `generateJWT` function generates a JWT token for the given user ID,

# Jwt Middleware
This package provides functionality for securing HTTP endpoints with JSON Web Tokens (JWTs) in a Go web application. It uses the jwt-go and go-jwt-middleware libraries to handle JWT validation and signing.

To use this package, you will need to set a SECRET environment variable with a hex-encoded secret key. This secret key will be used to sign and validate JWTs.

You can then use the InitMiddleware function to initialize a jwtMiddleware.JWTMiddleware instance with the secret key. This middleware can be used to secure an HTTP endpoint by passing it to the SecureEndpoint function along with the endpoint's path, a handler function, and a mux.Router instance.

For example:

```go
secret := auth.FindSecret()
middleware := auth.InitMiddleware(secret)

router := mux.NewRouter()
auth.SecureEndpoint("/secure", middleware, secureHandler, router)
```

This will secure the /secure endpoint with the initialized middleware. When a request is made to this endpoint, the middleware will check for a valid JWT in the request header and call the secureHandler function if the JWT is valid. If the JWT is invalid or not present, the middleware will return an error to the client.

You can also use the InitMiddleware function to customize the JWT validation and signing options. For example, you can specify a different method for extracting the JWT from the request (e.g. from a cookie or query parameter) by passing a custom Extractor function to the Options struct.

For more information on the jwt-go and go-jwt-middleware libraries, you can refer to their respective documentation.



## Auth Process Codex

1. Get the master secret key.
2. Make a new AES cipher block.
3. Make a new GCM cipher block which returns an AEAD object.
4. Verify the encrypted key's length.
5. Finally, "Open" the encrypted key by passing in `nil` for the destination, then the nonce which was prepended in the final key, then the actual encrypted key bytes (the latter part), and `nil` for extra data.

