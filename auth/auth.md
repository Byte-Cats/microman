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



### Auth Process Codex

    Get the master secret key.
    Make a new AES cipher block.
    Make a new GCM cipher block which returns an AEAD object.
    Verify the encrypted key’s length.
    Finally, “Open” the encrypted key by passing in nil for the destination, then the nonce which was prepended in the final key, then the actual encrypted key bytes (the latter part), and nil for extra data.
