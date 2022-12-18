package auth

import (
	"errors"

	jwt "github.com/dgrijalva/jwt-go"
)

// UserLogin takes in a username and password and returns a JWT token if the user is valid.
func UserLogin(username string, password string) (string, error) {
	// connect to database and retrieve user record
	user, err := getUserFromDB(username, password)
	if err != nil {
		return "", err
	}

	// generate JWT token
	secret := FindSecret()
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["id"] = user.ID
	claims["exp"] = time.Now().Add(time.Hour * 72).Unix()
	tokenString, err := token.SignedString(secret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// getUserFromDB retrieves a user record from the database by username and password.
// Returns an error if no matching record is found or if there is a problem connecting to the database.
func getUserFromDB(username string, password string) (User, error) {
	// query database and retrieve user record
	var user User
	if err := db.Where("username = ? AND password = ?", username, password).First(&user).Error; err != nil {
		return User{}, errors.New("Invalid username or password")
	}

	return user, nil
}
