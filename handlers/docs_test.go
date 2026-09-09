package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDocs(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/docs", nil)
	rec := httptest.NewRecorder()

	Docs(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Docs() status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got, want := rec.Body.String(), "Docs"; got != want {
		t.Errorf("Docs() body = %q, want %q", got, want)
	}
}
