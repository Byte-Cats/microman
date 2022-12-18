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

// UserCredentialRules represents the rules for validating a user's credentials.
type UserCredentialRules struct {
	MinUsernameLength int
	MaxUsernameLength int
	MinPasswordLength int
	AllowedUsernameSymbols string
	DisallowedUsernameStartSymbols string
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
	if err := validateUserInput(username, password); err != nil {
		return "", err
	}

	user, err := getUserFromDB(username, password)
	if err != nil {
		return "", err
	}

	return generateJWT(user.ID)
}



// handleCreateUser processes a request to create a new user with the given username and password.
// If the username is already in use, or if there is a problem connecting to the database, it returns an error.
func handleCreateUser(username string, password string) error {
	if err := validateUserInput(username, password); err != nil {
		return err
	}

	existingUser, err := getUserFromDBByUsername(username)
	if err == nil {
		return errors.New("Username is already in use")
	}

	hashedPassword, err := hashAndSaltPassword(password)
	if err != nil {
		return err
	}

	user :=User{
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

// Validate checks the user's credentials against the specified rules.
// Returns an error if the user's credentials are invalid, and nil otherwise.
func (u *User) Validate(rules *UserCredentialRules) error {
	if err := rules.ValidateUserCredentials(u.Username, u.Password); err != nil {
		return err
	}
	return nil
}

// ValidateUserCredentials checks the given username and password against the specified rules.
// Returns an error if either the username or password is invalid, and nil otherwise.
func (r *UserCredentialRules) ValidateUserCredentials(username string, password string) error {
	if len(username) < r.MinUsernameLength || len(username) > r.MaxUsernameLength {
		return fmt.Errorf("Username must be between %d and %d characters long", r.MinUsernameLength, r.MaxUsernameLength)
	}
	if len(password) < r.MinPasswordLength {
		return fmt.Errorf("Password must be at least %d characters long", r.MinPasswordLength)
	}
	if !r.IsUsernameValid(username) {
		return errors.New("Username must contain only letters, numbers, and thefollowing symbols: " + r.AllowedUsernameSymbols)
}
return nil
}


// User represents a user in the system.
type User struct {
ID int json:"id"
Username string json:"username"
Password string json:"password"
Rules *UserCredentialRules
}

// Validate checks the username and password of the user against the specified rules.
// Returns an error if either the username or password is invalid, and nil otherwise.
func (u *User) Validate() error {
return u.Rules.ValidateUserCredentials(u.Username, u.Password)
}

// IsUsernameValid checks if the given username is valid according to the rules.
// Returns true if the username is valid, and false otherwise.
func (r *UserCredentialRules) IsUsernameValid(username string) bool {
	if len(r.DisallowedUsernameStartSymbols) > 0 && strings.ContainsRune(r.DisallowedUsernameStartSymbols, rune(username[0])) {
		return false
	}
	for _, r := range username {
		if !unicode.IsLetter(r) && !unicode.IsNumber(r) && !strings.ContainsRune(r.AllowedUsernameSymbols, r) {
			return false
		}
	}
	return true
}

// containsInvalidCharacters checks the given string for invalid characters.
// Returns true if the string contains invalid characters, and false otherwise.
func containsInvalidCharacters(s string) bool {
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsNumber(r) && !unicode.IsSymbol(r) {
			return true
		}
	}
	return false
}

// isAlphanumeric checks if the given string consists only of alphanumeric characters.
// It returns true if the string is alphanumeric, or false otherwise.
func isAlphanumeric(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9') && !(c >= 'A' && c <= 'Z') && !(c >= 'a' && c <= 'z') {
			return false
		}
	}
	return true
}

// containsUppercase checks if the given string contains at least one uppercase letter.
// It returns true if the string contains an uppercase letter, or false otherwise.
func containsUppercase(s string) bool {
	for _, c := range s {
		if c >= 'A' && c <= 'Z' {
			return true
		}
	}
	return false
}

// containsLowercase checks if the given string contains at least one lowercase letter.
// It returns true if the string contains a lowercase letter, or false otherwise.
func containsLowercase(s string) bool {
	for _, c := range s {
		if c >= 'a' && c <= 'z' {
			return true
		}
	}
	return false
}

// containsDigit checks if the given string contains at least one digit.
// It returns true if the string contains a digit, or false otherwise.
func containsDigit(s string) bool {
	for _, c := range s {
		if c >= '0' && c <= '9' {
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

	// Validate input
	rules := UserCredentialRules{
		MinUsernameLength: 3,
		MaxUsernameLength: 20,
		MinPasswordLength: 8,
		AllowedUsernameSymbols: "_",
		DisallowedUsernameStartSymbols: "_",
	}
	if err := validateInput(username, password, &rules); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Get user from database
	user, err := getUserFromDBByUsername(username)
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Compare password hash
	if err := comparePasswordHash(user.Password, password); err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Generate JWT token
	token, err := generateJWT(user.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write([]byte(token))
}


func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Invalidate the session by deleting the corresponding cookie
	http.SetCookie(w, &http.Cookie{
		Name:   "session",
		Value:  "",
		MaxAge: -1,
	})
}

func resetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	// Validate the request
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Parse the request body
	var request struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Check if the email is registered
	user, err := getUserFromDBByEmail(request.Email)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Generate a password reset token and send it to the user's email
	token := generatePasswordResetToken(user.ID)
	if err := sendPasswordResetEmail(user.Email, token); err != nil {
		http.Error(w, "Failed to send password reset email", http.StatusInternalServerError)
		return
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	// Validate the request
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Parse the request body
	var request struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate the user's credentials
	rules := UserCredentialRules{
		MinUsernameLength: 3,
		MaxUsernameLength: 20,
		MinPasswordLength: 8,
		AllowedUsernameSymbols: "_",
		DisallowedUsernameStartSymbols: "_",
	}
	if err := rules.ValidateUserCredentials(request.Username, request.Password); err !=
if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
	http.Error(w, "Invalid request body", http.StatusBadRequest)
	return
}

}

// Validate the user's credentials
rules := UserCredentialRules{
	MinUsernameLength: 3,
	MaxUsernameLength: 20,
	MinPasswordLength: 8,
	AllowedUsernameSymbols: "_",
	DisallowedUsernameStartSymbols: "_",
}
if err := rules.ValidateUserCredentials(request.Username, request.Password); err != nil {
	http.Error(w, err.Error(), http.StatusBadRequest)
	return
}

// Create the user in the database
if err := handleCreateUser(request.Username, request.Password); err != nil {
	http.Error(w, err.Error(), http.StatusInternalServerError)
	return
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

