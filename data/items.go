package data

// CRUD logic for the `items` example resource (schema in schema.sql). This
// exists purely to demonstrate real database-backed request handling in
// handlers/add.go, get.go, edit.go and delete.go — it is intentionally a
// minimal demo domain model, not a real product resource.

import (
	"database/sql"
	"errors"
)

// Item is the example resource stored in the `items` table.
type Item struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

// ErrItemNotFound is returned by GetItem, UpdateItem and DeleteItem when no
// row matches the requested id.
var ErrItemNotFound = errors.New("item not found")

// CreateItem inserts a new item and returns it with its generated ID
// populated. Uses a parameterized query, never string concatenation.
func CreateItem(db *sql.DB, name, value string) (Item, error) {
	res, err := db.Exec("INSERT INTO items (name, value) VALUES (?, ?)", name, value)
	if err != nil {
		return Item{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Item{}, err
	}
	return Item{ID: int(id), Name: name, Value: value}, nil
}

// GetItem fetches a single item by id. Returns ErrItemNotFound if no row
// matches.
func GetItem(db *sql.DB, id int) (Item, error) {
	var item Item
	row := db.QueryRow("SELECT id, name, value FROM items WHERE id = ?", id)
	if err := row.Scan(&item.ID, &item.Name, &item.Value); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Item{}, ErrItemNotFound
		}
		return Item{}, err
	}
	return item, nil
}

// UpdateItem updates the name and value of the item with the given id.
// Returns ErrItemNotFound if no row matches.
func UpdateItem(db *sql.DB, id int, name, value string) (Item, error) {
	res, err := db.Exec("UPDATE items SET name = ?, value = ? WHERE id = ?", name, value, id)
	if err != nil {
		return Item{}, err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return Item{}, err
	}
	if rows == 0 {
		return Item{}, ErrItemNotFound
	}
	return Item{ID: id, Name: name, Value: value}, nil
}

// DeleteItem deletes the item with the given id. Returns ErrItemNotFound if
// no row matches.
func DeleteItem(db *sql.DB, id int) error {
	res, err := db.Exec("DELETE FROM items WHERE id = ?", id)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrItemNotFound
	}
	return nil
}
