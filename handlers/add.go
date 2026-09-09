package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/byte-cats/microman/data"
)

// AddRequest is the expected JSON body for POST /add.
type AddRequest struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Adder godoc
// @Summary Add an item
// @Description Creates a new row in the items table (see data/schema.sql) from a JSON body and returns the created item, including its generated id. Real MySQL-backed CRUD via the data package, demonstrating database wiring rather than a stub response.
// @Tags rest
// @Accept json
// @Produce json
// @Param item body handlers.AddRequest true "Item to create"
// @Success 201 {object} data.Item
// @Failure 400 {string} string "invalid request body"
// @Failure 500 {string} string "database error"
// @Router /add [post]
func Adder(w http.ResponseWriter, r *http.Request) {
	var req AddRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	db, err := data.Connect()
	if err != nil {
		http.Error(w, "database connection failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer data.Close(db)

	item, err := data.CreateItem(db, req.Name, req.Value)
	if err != nil {
		http.Error(w, "failed to create item: "+err.Error(), http.StatusInternalServerError)
		return
	}

	cont, err := data.JsonConvert(item)
	if err != nil {
		http.Error(w, "failed to encode response: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	writeString(w, cont)
}
