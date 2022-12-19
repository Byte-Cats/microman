package auth
//TODO: break this up into files

//     "database.go"

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


func getenv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}



