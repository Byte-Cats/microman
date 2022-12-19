package auth

// TODO: fix imports 


const (
	// ExpirationTime is the expiration time for the JWT token in hours.
	ExpirationTime = 72
	jwtSigningMethod = jwt.SigningMethodHS256
)

func generateJWT(userID int) (token string, err error) {
	secret := FindSecret()
	jwtToken := jwt.New(jwt.SigningMethodHS256)
	claims := jwtToken.Claims.(jwt.MapClaims)
	claims["id"] = userID
	claims["exp"] = time.Now().Add(time.Hour * ExpirationTime).Unix()
	token, err = jwtToken.SignedString(secret)
	return
}
	
type Claims struct {
	ID int `json:"id"`
	jwt.StandardClaims
}	

// VerifyToken takes in a JWT token and verifies it using the secret key.
// It returns the claims contained in the token if the token is valid, or an error if the token is invalid or has expired.
func VerifyToken(tokenString string) (*Claims, error) {
	secret := FindSecret()
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Check that the signing method is correct
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return secret, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("Invalid JWT token")
}

func refreshToken(refreshToken string) (string, error) {
  // Look up the user associated with the refresh token
  user, err := getUserFromRefreshToken(refreshToken)
  if err != nil {
    return "", err
  }

  // Generate a new JWT token for the user
  jwtToken, err := generateJWTToken(user)
  if err != nil {
    return "", err
  }

  return jwtToken, nil
}


// InitMiddleware initializes a jwtMiddleware.JWTMiddleware instance with the given secret key.
// This middleware can be used to secure an HTTP endpoint by passing it to the SecureEndpoint function.
func InitMiddleware(secret []byte) *jwtMiddleware.JWTMiddleware {
	middleware := jwtMiddleware.New(jwtMiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			return secret, nil
		},
		SigningMethod: jwt.SigningMethodHS256,
		Extractor:     jwtMiddleware.FromFirst(jwtMiddleware.FromAuthHeader),
	})
	return middleware
}

// SecureEndpoint secures an HTTP endpoint with the given middleware.
// When a request is made to this endpoint, the middleware will check for a valid JWT in the request header
// and call the handler function if the JWT is valid.
// If the JWT is invalid or not present, the middleware will return an error to the client.
func SecureEndpoint(path string, middleware *jwtMiddleware.JWTMiddleware, handler http.HandlerFunc, router *mux.Router) {
	router.Handle(path, negroni.New(
		negroni.HandlerFunc(middleware.HandlerWithNext),
		negroni.Wrap(http.HandlerFunc(handler)),
	))
}
