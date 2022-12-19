package auth

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

package auth

import (
"database/sql"
"errors"
"fmt"
"time"

"github.com/dgrijalva/jwt-go"
"golang.org/x/crypto/bcrypt"
)

// User represents a user in the system.
type User struct {
	ID       int    json:"id"
	Username string json:"username"
	Password string json:"password"
	Rules *CredentialRules
}

// ValidateCredentials checks if the provided username and password meet the requirements specified in the user's credential rules.
// It returns an error if the credentials are invalid, or nil if they are valid.
func ValidateCredentials(username string, password string, rules *CredentialRules) error {
	if len(username) < rules.MinUsernameLength {
		return errors.New(invalidUsernameLength)
	}
	if len(username) > rules.MaxUsernameLength {
		return errors.New(invalidUsernameLength)
	}
	if !strings.ContainsAny(username, rules.AllowedUsernameSymbols) {
		return errors.New(invalidUsernameCharacters)
	}
	if strings.ContainsAny(username[0:1], rules.DisallowedUsernameStartSymbols) {
		return errors.New(invalidUsernameStartCharacter)
	}
	if len(password) < rules.MinPasswordLength {
		return errors.New(invalidPasswordLength)
	}
	if !strings.ContainsAny(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		return errors.New(passwordMissingUppercase)
	}
	if !strings.ContainsAny(password, "abcdefghijklmnopqrstuvwxyz") {
		return errors.New(passwordMissingLowercase)
	}
	if !strings.ContainsAny(password, "0123456789") {
		return errors.New(passwordMissingDigit)
	}
	return nil
}



// FindUserByUsername looks for a user in the database with the given username and returns it.
// It returns an error if the user could not be found or if there was a problem with the database query.
func FindUserByUsername(username string) (*User, error) {
	row := database.QueryRow("SELECT id, username, password, min_username_length, max_username_length, min_password_length, allowed_username_symbols, disallowed_username_start_symbols FROM users WHERE username = ?", username)
	var user User
	err := row.Scan(&user.ID, &user.Username, &user.Password, &user.Rules.MinUsernameLength, &user.Rules.MaxUsernameLength, &user.Rules.MinPasswordLength, &user.Rules.AllowedUsernameSymbols, &user.Rules.DisallowedUsernameStartSymbols)
	if err == sql.ErrNoRows {
		return nil, errors.New(queryNoRows)
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}
