package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/byte-cats/microman/data"
)

// EditRequest is the expected JSON body for PUT /edit.
type EditRequest struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Editor godoc
// @Summary Edit an item
// @Description Updates the name/value of the row in the items table (see data/schema.sql) identified by the `id` query parameter, from a JSON body, and returns the updated item. Real MySQL-backed CRUD via the data package, demonstrating database wiring rather than a stub response.
// @Tags rest
// @Accept json
// @Produce json
// @Param id query int true "Item id"
// @Param item body handlers.EditRequest true "Fields to update"
// @Success 200 {object} data.Item
// @Failure 400 {string} string "missing/invalid id or request body"
// @Failure 404 {string} string "item not found"
// @Failure 500 {string} string "database error"
// @Router /edit [put]
func Editor(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.URL.Query().Get("id"))
	if err != nil {
		http.Error(w, "missing or invalid id query parameter", http.StatusBadRequest)
		return
	}

	var req EditRequest
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

	item, err := data.UpdateItem(db, id, req.Name, req.Value)
	if err != nil {
		if err == data.ErrItemNotFound {
			http.Error(w, "item not found", http.StatusNotFound)
			return
		}
		http.Error(w, "failed to update item: "+err.Error(), http.StatusInternalServerError)
		return
	}

	cont, err := data.JsonConvert(item)
	if err != nil {
		http.Error(w, "failed to encode response: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	writeString(w, cont)
}
