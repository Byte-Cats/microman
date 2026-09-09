package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestInfoDealer(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/info", nil)
	rec := httptest.NewRecorder()

	InfoDealer(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("InfoDealer() status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got, want := rec.Body.String(), Informant(); got != want {
		t.Errorf("InfoDealer() body = %q, want %q", got, want)
	}
}
