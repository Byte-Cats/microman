// UserCredentialRules represents the rules for validating a user's credentials.
type UserCredentialRules struct {
	MinUsernameLength     int
	MaxUsernameLength     int
	MinPasswordLength     int
	AllowedUsernameSymbols string
	DisallowedUsernameStartSymbols string
}
	
type CredentialRules UserCredentialRules
	



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


// Validate checks the user's credentials against the specified rules.
// Returns an error if the user's credentials are invalid, and nil otherwise.
func (u *User) Validate(rules *UserCredentialRules) error {
	if err := rules.ValidateUserCredentials(u.Username, u.Password); err != nil {
		return err
	}
	return nil
}
