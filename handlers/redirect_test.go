package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRedirect(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	Redirect(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Errorf("Redirect() status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if got, want := rec.Header().Get("Location"), "/docs"; got != want {
		t.Errorf("Redirect() Location header = %q, want %q", got, want)
	}
}
