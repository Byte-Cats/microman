//     Consider using the net/http package's BasicAuth function to check if the username and password provided in the request match the values in the Authorization header, instead of manually parsing the request form values. This can help make the code more concise and easier to read.
//     Consider using a dedicated function to hash and salt the password when creating a new user, rather than using bcrypt.GenerateFromPassword directly in the CreateUser function. This can help improve the readability and modularity of the code.
//     Consider using a dedicated function to handle the POST request to the login endpoint, rather than using an inline function. This can help improve the readability and modularity of the code.
//     Consider using a dedicated function to handle the POST request to the create user endpoint, rather than using an inline function. This can help improve the readability and modularity of the code.
//     Consider adding comments to the code to provide more information about the purpose and behavior of each function and variable. This can help improve the understandability of the code for other developers who may work on the project in the future.
//     Consider adding error handling code to the Decrypt and Encrypt functions to return more informative error messages when an error occurs. This can help make it easier to troubleshoot issues with the code.

import (
	"errors"
	"time"
  "database/sql"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
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

// UserLogin takes in a username and password and returns a JWT token if the user is valid.
func UserLogin(username string, password string) (string, error) {
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
	secret := FindSecret()
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["id"] = user.ID
	claims["exp"] = time.Now().Add(time.Hour * ExpirationTime).Unix()
	tokenString, err := token.SignedString(secret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// CreateUser takes in a username and password and creates a new user record in the database.
// Returns an error if the username is already in use or if there is a problem connecting to the database.
func CreateUser(username string, password string) error {
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
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
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

	var user User

	// Connect to the database
	db, err := sql.Open("mysql", "user:password@/database")
	if err != nil {
		return User{}, err
	}
	defer db.Close()

	// Query the database and retrieve the user record
	err = db.QueryRow("SELECT id, username, password FROM users WHERE username=? AND password=?", username, password).Scan(&user.ID, &user.Username, &user.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			return User{}, errors.New("Invalid username or password")
		}
		return User{}, err
	}

	return user, nil
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
func VerifyToken(tokenString string) (jwt.MapClaims, error) {
	secret := FindSecret()

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// check that the signing method is correct
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return secret, nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("Invalid token")
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

// VerifyJWT verifies a JWT token and returns the claims contained in it.
// Returns an error if the token is invalid or if there is a problem verifying it.
func VerifyJWT(tokenString string) (*Claims, error) {
	secret := FindSecret()
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return secret, nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("Invalid JWT token")
	}
	return token.Claims.(*Claims), nil
}



// DeleteUser takes in a user ID and deletes the corresponding user record from the database.
// Returns an error if there is a problem connecting to the database.
func DeleteUser(userID int) error {
	if err := db.Where("id = ?", userID).Delete(User{}).Error; err != nil {
		return err
	}

	return nil
}

