package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ExpirationTime is the expiration time for the JWT token in hours.
const ExpirationTime = 72

var jwtSigningMethod = jwt.SigningMethodHS256

func generateJWT(userID int32) (token string, err error) {
	secret, err := FindSecret("SECRET", "", "", "")
	if err != nil {
		return "", err
	}
	jwtToken := jwt.New(jwt.SigningMethodHS256)
	claims := jwtToken.Claims.(jwt.MapClaims)
	claims["id"] = userID
	claims["exp"] = time.Now().Add(time.Hour * ExpirationTime).Unix()
	token, err = jwtToken.SignedString([]byte(secret.Value))
	return
}

type Claims struct {
	ID int `json:"id"`
	jwt.RegisteredClaims
}

// VerifyToken takes in a JWT token and verifies it using the secret key.
// It returns the claims contained in the token if the token is valid, or an error if the token is invalid or has expired.
func VerifyToken(tokenString string) (*Claims, error) {
	secret, err := FindSecret("SECRET", "", "", "")
	if err != nil {
		return nil, err
	}
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Check that the signing method is correct
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret.Value), nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("invalid JWT token")
}
