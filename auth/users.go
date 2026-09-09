package auth

import (
	"database/sql"
	"errors"
	"strings"
)

// User represents a user in the system.
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
	Rules    *CredentialRules
}

// Sentinel errors so callers can distinguish these specific conditions from
// generic DB failures with errors.Is, rather than string-matching messages.
var (
	errUsernameTaken = errors.New(usernameTaken)
	errUserNotFound  = errors.New(userNotFound)
	errQueryNoRows   = errors.New(queryNoRows)
)

// validationInputError wraps an error returned by validateUserInput so
// callers (route.go's registerHandler) can distinguish "the submitted
// username/password don't meet the shape rules" (a 400, the caller's fault)
// from every other CreateUser failure (a 409 for a duplicate username, or a
// 500 for a real DB error) using errors.As instead of string-matching.
type validationInputError struct {
	err error
}

func (v *validationInputError) Error() string { return v.err.Error() }
func (v *validationInputError) Unwrap() error { return v.err }

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
	db, err := getDB()
	if err != nil {
		return nil, err
	}
	user := User{Rules: &CredentialRules{}}
	row := db.QueryRow("SELECT id, username, password, min_username_length, max_username_length, min_password_length, allowed_username_symbols, disallowed_username_start_symbols FROM users WHERE username = ?", username)
	err = row.Scan(&user.ID, &user.Username, &user.Password, &user.Rules.MinUsernameLength, &user.Rules.MaxUsernameLength, &user.Rules.MinPasswordLength, &user.Rules.AllowedUsernameSymbols, &user.Rules.DisallowedUsernameStartSymbols)
	if err == sql.ErrNoRows {
		return nil, errQueryNoRows
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// defaultUserCredentialRules are the credential-shape rules applied to newly
// created accounts when the caller doesn't specify their own. They match the
// rules LoginHandler already builds inline in login.go, kept here as the one
// place CreateUser sources its defaults from.
func defaultUserCredentialRules() *UserCredentialRules {
	return &UserCredentialRules{
		MinUsernameLength:              3,
		MaxUsernameLength:              20,
		MinPasswordLength:              8,
		AllowedUsernameSymbols:         "_",
		DisallowedUsernameStartSymbols: "_",
	}
}

// CreateUser validates username/password against rules (or
// defaultUserCredentialRules if rules is nil), rejects the request if the
// username is already taken, hashes the password, and inserts the new user
// row. The inserted row records the credential rules that were applied so
// FindUserByUsername (and thus login) can later re-validate against the same
// shape the account was created under.
//
// It returns an error wrapping errUsernameTaken (checkable with errors.Is)
// if the username already exists, so callers can map that specific case to
// a 409 without string-matching error text.
func CreateUser(username, password string, rules *UserCredentialRules) (*User, error) {
	if rules == nil {
		rules = defaultUserCredentialRules()
	}

	if err := validateUserInput(username, password, rules); err != nil {
		return nil, &validationInputError{err}
	}

	if _, err := FindUserByUsername(username); err == nil {
		return nil, errUsernameTaken
	} else if !errors.Is(err, errQueryNoRows) {
		return nil, err
	}

	hashed, err := hashAndSaltPassword(password)
	if err != nil {
		return nil, err
	}

	db, err := getDB()
	if err != nil {
		return nil, err
	}

	result, err := db.Exec(
		"INSERT INTO users (username, password, min_username_length, max_username_length, min_password_length, allowed_username_symbols, disallowed_username_start_symbols) VALUES (?, ?, ?, ?, ?, ?, ?)",
		username, string(hashed), rules.MinUsernameLength, rules.MaxUsernameLength, rules.MinPasswordLength, rules.AllowedUsernameSymbols, rules.DisallowedUsernameStartSymbols,
	)
	if err != nil {
		return nil, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	return &User{
		ID:       int(id),
		Username: username,
		Password: string(hashed),
		Rules:    (*CredentialRules)(rules),
	}, nil
}

// RemoveUser deletes the user with the given username. It returns an error
// wrapping errUserNotFound (checkable with errors.Is) if no such user
// exists, so callers can distinguish "nothing to delete" from a real DB
// error.
func RemoveUser(username string) error {
	db, err := getDB()
	if err != nil {
		return err
	}

	result, err := db.Exec("DELETE FROM users WHERE username = ?", username)
	if err != nil {
		return err
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return errUserNotFound
	}
	return nil
}
