package auth
//TODO: break this up into files

//     "constants.go"
//     "rules.go"
//     "secrets.go"
//     "users.go"
//     "database.go"
//     "jwt.go"
//     "password.go"

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"time"
	"encoding/hex"
	"log"
	"strings"

	jwtMiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/form3tech-oss/jwt-go"
	"github.com/gorilla/mux"
	"github.com/urfave/negroni"
	"golang.org/x/crypto/bcrypt"
	"net/http"

)

const (
	// ExpirationTime is the expiration time for the JWT token in hours.
	ExpirationTime = 72
	jwtSigningMethod = jwt.SigningMethodHS256
	
	// Constants for string values
	invalidUsernameLength = "Invalid username length"
	invalidUsernameCharacters = "Invalid username characters"
	invalidUsernameStartCharacter = "Invalid username start character"
	invalidPasswordLength = "Invalid password length"
	passwordMissingUppercase = "Password missing uppercase letter"
	passwordMissingLowercase = "Password missing lowercase letter"
	passwordMissingDigit = "Password missing digit"
	databaseError = "Database error"
	queryError = "Query error"
	queryNoRows = "Query returned no rows"
	usernameTaken = "Username already taken"
	incorrectPassword = "Incorrect password"
	unauthorized = "Unauthorized"
	invalidToken = "Invalid token"
	secretNotSetErrorMessage        = "secret value is not set"
	negativeExpirationErrorMessage = "expiration time is negative"

	
// UserCredentialRules represents the rules for validating a user's credentials.
type UserCredentialRules struct {
	MinUsernameLength     int
	MaxUsernameLength     int
	MinPasswordLength     int
	AllowedUsernameSymbols string
	DisallowedUsernameStartSymbols string
}
	
type CredentialRules UserCredentialRules
	
type Secret struct {
    Value string
    ExpiresAt time.Time
}
	
	
// User represents a user in the system.
type User struct {
    ID       int    json:"id"
    Username string json:"username"
    Password string json:"password"
    Rules *CredentialRules
}


	
var database *sql.DB

func initDB() {
	var err error
	db, err = ConnectDB("user", "password", "localhost", "3306", "auth")
	if err != nil {
		log.Fatal(err)
	}
}
	

func ConnectDB(user, password, host, port, dbname string) (*sql.DB, error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", user, password, host, port, dbname)
	database, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}

	if err = database.Ping(); err != nil {
		return nil, err
	}

	return database, nil
}


func CloseDB(db *sql.DB) error {
	return db.Close()
}
	

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


func FindSecret(secretEnvVar, expirationEnvVar, defaultSecret, defaultExpiration string) (*Secret, error) {
	secretValue := getenv(secretEnvVar, defaultSecret)
	if secretValue == "" {
		return nil, errors.New(secretNotSetErrorMessage)
	}

	expiration, err := time.ParseDuration(getenv(expirationEnvVar, defaultExpiration))
	if err != nil {
		return nil, err
	}
	if expiration < 0 {
		return nil, errors.New(negativeExpirationErrorMessage)
	}

	secretBits, err := hex.DecodeString(secretValue)
	if err != nil {
		return nil, err
	}

	return &Secret{
		Value: secretBits,
		ExpiresAt: time.Now().Add(expiration),
	}, nil
}

// hashAndSaltPassword hashes and salts the given password using bcrypt.
// Returns the hashed password as a byte slice, and any error that occurred.
func hashAndSaltPassword(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
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

// validateUserInput validates the given username and password according to the rules specified in the UserCredentialRules struct.
// Returns an error if the input is invalid.
func validateUserInput(username, password string, rules *UserCredentialRules) error {
	// Validate username
	if len(username) < rules.MinUsernameLength || len(username) > rules.MaxUsernameLength {
		return errors.New(invalidUsernameLength)
	}
	for _, c := range username {
		if !strings.Contains(rules.AllowedUsernameSymbols, string(c)) {
			return errors.New(invalidUsernameCharacters)
		}
		if strings.Contains(rules.DisallowedUsernameStartSymbols, string(c)) {
			return errors.New(invalidUsernameStartCharacter)
		}
	}
	// Validate password
	if len(password) < rules.MinPasswordLength {
		return errors.New(invalidPasswordLength)
	}
	if !containsUppercase(password) {
		return errors.New(passwordMissingUppercase)
	}
	if !containsLowercase(password) {
		return errors.New(passwordMissingLowercase)
	}
	if !containsDigit(password) {
		return errors.New(passwordMissingDigit)
	}
	return nil
}


// handleUserLogin processes a login request for the given username and password.
// If the user is valid, it returns a JWT token. Otherwise, it returns an error.
func handleUserLogin(username, password string) (string, error) {
	if err := validateUserInput(username, password); err != nil {
		return "", err
	}

	user, err := getUserFromDB(username)
	if err != nil {
		return "", err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return "", errors.New("Invalid username or password")
	}

	return generateJWT(user.ID)
}


// createUser creates a new user in the database with the given username and password.
// Returns the ID of the new user and any error that occurred.
func createUser(username, password string, rules *UserCredentialRules) (int, error) {
	row := db.QueryRow("SELECT id FROM users WHERE username=?", username)
	
	err := validateUserInput(username, password, rules)
	if err != nil {
		return 0, err
	}
	hashedPassword, err := hashAndSaltPassword(password)
	if err != nil {
		return 0, err
	}
	query := "INSERT INTO users (username, password) VALUES (?, ?)"
	res, err := db.Exec(query, username, hashedPassword)
	if err != nil {
		return 0, errors.New(databaseError)
	}
	userID, err := res.LastInsertId()
	if err != nil {
		return 0, errors.New(databaseError)
	}
	return int(userID), nil
}


// getUserFromDB retrieves a user record from the database by either their username or their ID.
// Returns an error if no matching record is found, if there is a problem connecting to the database,
// or if the input is invalid.
func getUserFromDB(input interface{}) (User, error) {
	user := User{}
	var err error

	switch v := input.(type) {
	case string:
		// Search by username
		err = db.Where("username = ?", v).First(&user).Error
	case int:
		// Search by ID
		err = db.Where("id = ?", v).First(&user).Error
	default:
		return user, errors.New("Invalid input type")
	}

	if err == sql.ErrNoRows {
		return user, errors.New("User not found")
	}
	if err != nil {
		return user, err
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
// Returns an error if there is a problem connecting to the database or if the user could not be found.
func DeleteUser(userID int) error {
	// Check if the user exists
	var user User
	row := db.QueryRow("SELECT * FROM users WHERE id = ?", userID)
	if err := row.Scan(&user.ID, &user.Username, &user.Password, &user.Rules); err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("User with ID %d not found", userID)
		}
		return fmt.Errorf("Failed to query database: %v", err)
	}

	// Delete the user
	_, err := db.Exec("DELETE FROM users WHERE id = ?", userID)
	if err != nil {
		return fmt.Errorf("Failed to delete user: %v", err)
	}

	return nil
}

// isUsernameTaken checks if the given username is already taken in the database.
// It returns true if the username is taken, or false otherwise.
func isUsernameTaken(username string) bool {
	var user User
	query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", username)
	if err := db.QueryRow(query).Scan(&user.ID, &user.Username, &user.Password); err != nil {
		if err == sql.ErrNoRows {
			// The username is available
			return false
		} else {
			// An error occurred while querying the database
			return true
		}
	}
	// The username is already taken
	return true
}



func handleRegister(w http.ResponseWriter, r *http.Request) {
	// Parse the request body to get the new user's username and password
	var newUser User
	if err := json.NewDecoder(r.Body).Decode(&newUser); err != nil {
		http.Error(w, "Failed to parse request body", http.StatusBadRequest)
		return
	}

	// Validate the new user's credentials
	if err := validateCredentials(newUser.Username, newUser.Password); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check if the username is already taken
	if isUsernameTaken(newUser.Username) {
		http.Error(w, "Username already taken", http.StatusBadRequest)
		return
	}

	// Hash and salt the password
	hashedPassword, err := hashAndSaltPassword(newUser.Password)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	// Insert the new user into the database
	query := fmt.Sprintf("INSERT INTO users (username, password) VALUES ('%s', '%s')", newUser.Username, hashedPassword)
	if _, err := db.Exec(query); err != nil {
		http.Error(w, "Failed to insert new user into database", http.StatusInternalServerError)
		return
	}

	// Return a success response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Successfully registered new user"})
}

// Register creates a new user in the system with the given username and password.
// Returns an error if the username is already taken or if the password is invalid.
func Register(username, password string) error {
	// Validate the password
	if err := validatePassword(password); err != nil {
		return err
	}

	// Check if username is already taken
	if err := checkUsernameTaken(username); err != nil {
		return err
	}

	// Hash and salt the password
	hashedPassword, err := hashAndSaltPassword(password)
	if err != nil {
		return err
	}

	// Create the new user
	user := User{
		Username: username,
		Password: hashedPassword,
	}
	if err := createUser(user); err != nil {
		return err
	}

	return nil
}

func getenv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
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
