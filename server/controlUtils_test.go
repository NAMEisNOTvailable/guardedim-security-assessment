package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReplaceIPHandlerRejectsBasicBadRequests(t *testing.T) {
	handler := httpHandleReplaceIP(nil)

	tests := []struct {
		name   string
		method string
		body   string
		status int
	}{
		{
			name:   "wrong method",
			method: http.MethodGet,
			body:   "",
			status: http.StatusMethodNotAllowed,
		},
		{
			name:   "invalid json",
			method: http.MethodPost,
			body:   "{",
			status: http.StatusBadRequest,
		},
		{
			name:   "invalid ip",
			method: http.MethodPost,
			body:   `{"user_id":1,"ip_address":"not-an-ip"}`,
			status: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/control/replace-ip", strings.NewReader(tt.body))
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d; body=%q", rec.Code, tt.status, rec.Body.String())
			}
		})
	}
}
