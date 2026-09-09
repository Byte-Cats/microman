package handlers

import (
	"net/http"
	"strconv"

	"github.com/byte-cats/microman/data"
)

// Get godoc
// @Summary Get an item
// @Description Fetches a single row from the items table (see data/schema.sql) by its id, passed as the `id` query parameter, and returns it as JSON. Real MySQL-backed CRUD via the data package, demonstrating database wiring rather than a stub response.
// @Tags rest
// @Produce json
// @Param id query int true "Item id"
// @Success 200 {object} data.Item
// @Failure 400 {string} string "missing or invalid id"
// @Failure 404 {string} string "item not found"
// @Failure 500 {string} string "database error"
// @Router /get [get]
func Get(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.URL.Query().Get("id"))
	if err != nil {
		http.Error(w, "missing or invalid id query parameter", http.StatusBadRequest)
		return
	}

	db, err := data.Connect()
	if err != nil {
		http.Error(w, "database connection failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer data.Close(db)

	item, err := data.GetItem(db, id)
	if err != nil {
		if err == data.ErrItemNotFound {
			http.Error(w, "item not found", http.StatusNotFound)
			return
		}
		http.Error(w, "failed to get item: "+err.Error(), http.StatusInternalServerError)
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
