package handlers

import (
	"net/http"

	"github.com/byte-cats/microman/data"
)

type Dammit struct {
	well string
	ok   int
}

// Adder handler that adds something to the database
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
