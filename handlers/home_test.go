package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHome(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/home", nil)
	rec := httptest.NewRecorder()

	Home(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Home() status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got, want := rec.Body.String(), HomeSecrets(); got != want {
		t.Errorf("Home() body = %q, want %q", got, want)
	}
}
