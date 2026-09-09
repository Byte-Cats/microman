package handlers

import (
	"net/http"
	"strconv"

	"github.com/byte-cats/microman/data"
)

// DeleteResponse is the JSON body returned by DELETE /delete on success.
type DeleteResponse struct {
	Deleted bool `json:"deleted"`
	ID      int  `json:"id"`
}

// Deleter godoc
// @Summary Delete an item
// @Description Deletes the row in the items table (see data/schema.sql) identified by the `id` query parameter and confirms deletion as JSON. Real MySQL-backed CRUD via the data package, demonstrating database wiring rather than a stub response.
// @Tags rest
// @Produce json
// @Param id query int true "Item id"
// @Success 200 {object} handlers.DeleteResponse
// @Failure 400 {string} string "missing or invalid id"
// @Failure 404 {string} string "item not found"
// @Failure 500 {string} string "database error"
// @Router /delete [delete]
func Deleter(w http.ResponseWriter, r *http.Request) {
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

	if err := data.DeleteItem(db, id); err != nil {
		if err == data.ErrItemNotFound {
			http.Error(w, "item not found", http.StatusNotFound)
			return
		}
		http.Error(w, "failed to delete item: "+err.Error(), http.StatusInternalServerError)
		return
	}

	cont, err := data.JsonConvert(DeleteResponse{Deleted: true, ID: id})
	if err != nil {
		http.Error(w, "failed to encode response: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	writeString(w, cont)
}
