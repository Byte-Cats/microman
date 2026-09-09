package auth

import (
	"database/sql"
	"fmt"
	"sync"
)

var (
	database   *sql.DB
	initDBOnce sync.Once
	initDBErr  error
)

// getDB lazily opens (and pings) the package-level MySQL connection the
// first time it's needed, and returns the same *sql.DB on every subsequent
// call. This exists because nothing was ever calling the old initDB() at
// startup, which meant database stayed nil and any query against it (e.g.
// FindUserByUsername) would nil-pointer-dereference the first time it was
// actually exercised. Every DB-touching function in this package should call
// getDB() instead of reading the package var directly.
//
// Connection parameters come from AUTH_DB_USER/AUTH_DB_PASSWORD/AUTH_DB_HOST/
// AUTH_DB_PORT/AUTH_DB_NAME env vars, falling back to the same defaults the
// old initDB() hardcoded (user/password/localhost/3306/auth) so behavior is
// unchanged for anyone already relying on those defaults.
func getDB() (*sql.DB, error) {
	initDBOnce.Do(func() {
		database, initDBErr = ConnectDB(
			getenv("AUTH_DB_USER", "user"),
			getenv("AUTH_DB_PASSWORD", "password"),
			getenv("AUTH_DB_HOST", "localhost"),
			getenv("AUTH_DB_PORT", "3306"),
			getenv("AUTH_DB_NAME", "auth"),
		)
	})
	return database, initDBErr
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
