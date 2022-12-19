package auth

import (
	"database/sql"
	"fmt"
	"log"
)

var database *sql.DB

func initDB() {
	var err error
	database, err = ConnectDB("user", "password", "localhost", "3306", "auth")
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
