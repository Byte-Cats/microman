package auth

import (
	"errors"
	"testing"
)

// TestCreateUserRejectsInvalidInputBeforeTouchingDB verifies that CreateUser
// validates the submitted username/password against the credential rules
// before it ever attempts to reach the database. That ordering matters: it's
// what lets this test run (and assert a specific, non-DB error) without a
// live MySQL instance, and it's the mechanism registerHandler relies on to
// turn a badly-shaped request into a 400 rather than a 500.
func TestCreateUserRejectsInvalidInputBeforeTouchingDB(t *testing.T) {
	rules := &UserCredentialRules{
		MinUsernameLength:              3,
		MaxUsernameLength:              10,
		MinPasswordLength:              8,
		AllowedUsernameSymbols:         "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_",
		DisallowedUsernameStartSymbols: "_0123456789",
	}

	cases := []struct {
		name     string
		username string
		password string
		wantErr  string
	}{
		{"username too short", "ab", "Passw0rd", invalidUsernameLength},
		{"username too long", "verylongusername", "Passw0rd", invalidUsernameLength},
		{"username has disallowed character", "go@user", "Passw0rd", invalidUsernameCharacters},
		{"username starts with disallowed symbol", "0user", "Passw0rd", invalidUsernameStartCharacter},
		{"password too short", "gooduser", "Pass1", invalidPasswordLength},
		{"password missing uppercase", "gooduser", "password1", passwordMissingUppercase},
		{"password missing lowercase", "gooduser", "PASSWORD1", passwordMissingLowercase},
		{"password missing digit", "gooduser", "Password", passwordMissingDigit},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			user, err := CreateUser(tc.username, tc.password, rules)
			if user != nil {
				t.Errorf("CreateUser(%q, %q) returned a user, want nil", tc.username, tc.password)
			}
			if err == nil {
				t.Fatalf("CreateUser(%q, %q) = nil error, want %q", tc.username, tc.password, tc.wantErr)
			}
			if err.Error() != tc.wantErr {
				t.Errorf("CreateUser(%q, %q) error = %q, want %q", tc.username, tc.password, err.Error(), tc.wantErr)
			}
			var validationErr *validationInputError
			if !errors.As(err, &validationErr) {
				t.Errorf("CreateUser(%q, %q) error is not a *validationInputError: %v (%T)", tc.username, tc.password, err, err)
			}
		})
	}
}

// TestCreateUserDefaultRulesAppliedWhenNil verifies CreateUser falls back to
// defaultUserCredentialRules (rather than panicking on a nil rules) and that
// those defaults still reject an obviously-too-short username without
// touching the database.
func TestCreateUserDefaultRulesAppliedWhenNil(t *testing.T) {
	user, err := CreateUser("ab", "Passw0rd", nil)
	if user != nil {
		t.Errorf("CreateUser with nil rules returned a user, want nil")
	}
	if err == nil || err.Error() != invalidUsernameLength {
		t.Errorf("CreateUser with nil rules error = %v, want %q", err, invalidUsernameLength)
	}
}
