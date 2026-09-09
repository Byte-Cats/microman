package auth

import "testing"

func TestContainsUppercase(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"has uppercase", "Hello", true},
		{"all lowercase", "hello", false},
		{"digits only", "12345", false},
		{"empty string", "", false},
		{"symbols only", "!@#$", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := containsUppercase(tc.in); got != tc.want {
				t.Errorf("containsUppercase(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestContainsLowercase(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"has lowercase", "Hello", true},
		{"all uppercase", "HELLO", false},
		{"digits only", "12345", false},
		{"empty string", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := containsLowercase(tc.in); got != tc.want {
				t.Errorf("containsLowercase(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestContainsDigit(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"has digit", "abc123", true},
		{"no digit", "abcdef", false},
		{"empty string", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := containsDigit(tc.in); got != tc.want {
				t.Errorf("containsDigit(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestIsAlphanumeric(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"letters and digits", "abc123XYZ", true},
		{"empty string", "", true},
		{"contains space", "abc 123", false},
		{"contains symbol", "abc_123", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isAlphanumeric(tc.in); got != tc.want {
				t.Errorf("isAlphanumeric(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func testRules() *UserCredentialRules {
	return &UserCredentialRules{
		MinUsernameLength:              3,
		MaxUsernameLength:              10,
		MinPasswordLength:              8,
		AllowedUsernameSymbols:         "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_",
		DisallowedUsernameStartSymbols: "_0123456789",
	}
}

func TestValidateUserInput(t *testing.T) {
	cases := []struct {
		name     string
		username string
		password string
		wantErr  string // expected error message, "" means no error
	}{
		{"valid credentials", "gooduser", "Passw0rd", ""},
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
			err := validateUserInput(tc.username, tc.password, testRules())
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("validateUserInput(%q, %q) = %v, want nil", tc.username, tc.password, err)
				}
				return
			}
			if err == nil || err.Error() != tc.wantErr {
				t.Errorf("validateUserInput(%q, %q) = %v, want error %q", tc.username, tc.password, err, tc.wantErr)
			}
		})
	}
}

func TestIsUsernameValid(t *testing.T) {
	rules := &UserCredentialRules{
		AllowedUsernameSymbols:         "_",
		DisallowedUsernameStartSymbols: "_0123456789",
	}
	cases := []struct {
		name     string
		username string
		want     bool
	}{
		{"valid letters only", "gooduser", true},
		{"valid with allowed symbol", "user_name", true},
		{"starts with disallowed underscore", "_user", false},
		{"starts with disallowed digit", "9user", false},
		{"contains disallowed symbol", "user!name", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rules.IsUsernameValid(tc.username); got != tc.want {
				t.Errorf("IsUsernameValid(%q) = %v, want %v", tc.username, got, tc.want)
			}
		})
	}
}
