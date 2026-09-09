package handlers

import (
	"net/http"

	"github.com/byte-cats/microman/data"
)

type Dammit struct {
	well string
	ok   int
}

// Adder godoc
// @Summary Add a resource
// @Description Stub handler that is meant to add something to the database; currently builds a placeholder struct, JSON-encodes it via data.JsonConvert, and writes it back. The route is registered without a method restriction, so it currently responds to any HTTP method.
// @Tags rest
// @Produce json
// @Success 200 {object} object "placeholder JSON payload"
// @Router /add [post]
func Adder(w http.ResponseWriter, r *http.Request) {
	d := Dammit{
		well: "yes",
		ok:   1,
	}
	cont, _ := data.JsonConvert(d)
	_, err := w.Write([]byte(cont))
	if err != nil {
		return
	}

}
