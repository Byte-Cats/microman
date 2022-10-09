package auth

// User represents a user in the system.
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
