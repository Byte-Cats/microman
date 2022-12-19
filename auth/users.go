	
	
// User represents a user in the system.
type User struct {
    ID       int    json:"id"
    Username string json:"username"
    Password string json:"password"
    Rules *CredentialRules
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



