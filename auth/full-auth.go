package auth

import (
	"errors"
	"time"
 	"database/sql"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
	"net/http"
)
const (
	// ExpirationTime is the expiration time for the JWT token in hours.
	ExpirationTime = 72
)

// User represents a user in the system.
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	ID int `json:"id"`
	jwt.StandardClaims
}

// generateJWT generates a JWT token for the given user ID.
// It returns the JWT token as a string, and any error that occurred.
func generateJWT(userID int) (string, error) {
	secret := FindSecret()
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["id"] = userID
	claims["exp"] = time.Now().Add(time.Hour * ExpirationTime).Unix()
	return token.SignedString(secret)
}

// hashAndSaltPassword hashes and salts the given password using bcrypt.
// Returns the hashed password as a byte slice, and any error that occurred.
func hashAndSaltPassword(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
}

// handleUserLogin processes a login request for the given username and password.
// If the user is valid, it returns a JWT token. Otherwise, it returns an error.
func handleUserLogin(username string, password string) (string, error) {
// Validate input
if err := validateInput(username, password); err != nil {
return "", err
}
// Connect to database and retrieve user record
user, err := getUserFromDB(username, password)
if err != nil {
	return "", err
}

// Generate JWT token
return generateJWT(user.ID)
}


// handleCreateUser processes a request to create a new user with the given username and password.
// If the username is already in use, or if there is a problem connecting to the database, it returns an error.
func handleCreateUser(username string, password string) error {
	// Validate input
	if err := validateInput(username, password); err != nil {
		return err
	}

	// Check if username is already in use
	existingUser, err := getUserFromDBByUsername(username)
	if err == nil {
		return errors.New("Username is already in use")
	}

	// Hash and salt password
	hashedPassword, err := hashAndSaltPassword(password)
	if err != nil {
		return err
	}

	// Create new user record
	user := User{
		Username: username,
		Password: string(hashedPassword),
	}
	if err := db.Create(&user).Error; err != nil {
		return err
	}

	return nil
}


// getUserFromDB retrieves a user record from the database by username and password.
// Returns an error if no matching record is found, if there is a problem connecting to the database,
// or if the input is invalid.
func getUserFromDB(username string, password string) (User, error) {
	// Validate input
	if err := validateInput(username, password); err != nil {
		return User{}, err
	}

	// Connect to database and retrieve user record
	user := User{}
	err := db.Where("username = ?", username).First(&user).Error
	if err != nil {
		return User{}, errors.New("Invalid username or password")
	}

	// Check password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return User{}, errors.New("Invalid username or password")
	}

	return user, nil
}

// getUserFromDBByUsername retrieves a user record from the database by username.
// Returns an error if no matching record is found, or if there is a problem connecting to the database.
func getUserFromDBByUsername(username string) (User, error) {
	// Validate input
	if err := validateInput(username, ""); err != nil {
		return User{}, err
	}

	// Connect to database and retrieve user record
	user := User{}
	err := db.Where("username = ?", username).First(&user).Error
	if err != nil {
		return User{}, err
	}

	return user, nil
}

// validateInput checks the given username and password for invalid characters or empty values.
// Returns an error if the input is invalid.
func validateInput(username string, password string) error {
	if username == "" || password == "" {
		return errors.New("Username and password are required")
	}
	if containsInvalidCharacters(username) || containsInvalidCharacters(password) {
		return errors.New("Username and password can only contain alphanumeric characters")
	}
	return nil
}

// containsInvalidCharacters checks the given string for invalid characters.
// Returns true if the string contains invalid characters, and false otherwise.
func containsInvalidCharacters(s string) bool {
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsNumber(r) {
			return true
		}
	}
	return false
}



// Encrypt will encrypt a raw string to
// an encrypted value
// an encrypted value has an IV (nonce) + actual encrypted value
// when we decrypt, we only decrypt the latter part
func Encrypt(key []byte) ([]byte, error) {
	secretKey := FindSecret()

	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, aesgcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(iv, iv, key, nil)

	return ciphertext, nil
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	token, err := auth.UserLogin(username, password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	w.Write([]byte(token))
}

// Decrypt will return the original value of the encrypted string
func Decrypt(encryptedKey []byte) ([]byte, error) {
	secretKey := FindSecret()

	block, err := aes.NewCipher(secretKey)

	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(encryptedKey) < aesgcm.NonceSize() {
		// worth panicking when encrypted key is bad
		panic("Malformed encrypted key")
	}

	return aesgcm.Open(
		nil,
		encryptedKey[:aesgcm.NonceSize()],
		encryptedKey[aesgcm.NonceSize():],
		nil,
	)
}


// ChangePassword takes in a user ID, the current password, and the new password and updates the user's password in the database if the current password is correct. Returns an error if the current password is incorrect or there is an error updating the password.
func ChangePassword(userID int, currentPassword string, newPassword string) error {
	// connect to database and retrieve user record
	user, err := getUserFromDB(userID)
	if err != nil {
		return err
	}

	// check if current password is correct
	if user.Password != currentPassword {
		return errors.New("Incorrect current password")
	}

	// update password in database
	user.Password = newPassword
	if err := updateUserInDB(user); err != nil {
		return err
	}

	return nil
}

// ResetPassword takes in a user ID and a new password and resets the user's password in the database. Returns an error if there is an error resetting the password.
func ResetPassword(userID int, newPassword string) error {
	// connect to database and retrieve user record
	user, err := getUserFromDB(userID)
	if err != nil {
		return err
	}

	// update password in database
	user.Password = newPassword
	if err := updateUserInDB(user); err != nil {
		return err
	}

	return nil
}

// Logout takes in a JWT token and invalidates it so that it can no longer be used for authentication.
func Logout(token string) error {
	// parse token to get claims
	parsedToken, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		return FindSecret(), nil
	})
	if err != nil {
		return err
	}
	claims := parsedToken.Claims.(jwt.MapClaims)

	// get user ID from claims
	userID, ok := claims["id"].(float64)
	if !ok {
		return errors.New("Invalid token")
	}

	// invalidate token in database
	if err := invalidateTokenInDB(int(userID)); err != nil {
		return err
	}

	return nil
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

// DeleteUser takes in a user ID and deletes the corresponding user record from the database.
// Returns an error if there is a problem connecting to the database.
func DeleteUser(userID int) error {
	if err := db.Where("id = ?", userID).Delete(User{}).Error; err != nil {
		return err
	}

	return nil
}

