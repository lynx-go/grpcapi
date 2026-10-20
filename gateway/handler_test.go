package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewHandler(t *testing.T) {
	mux := NewMux(MuxOptions{})
	if err := mux.HandlePath("GET", "/ping", func(w http.ResponseWriter, _ *http.Request, _ map[string]string) {
		_, _ = w.Write([]byte("pong"))
	}); err != nil {
		t.Fatal(err)
	}
	h := NewHandler(HandlerOptions{
		Gateway: mux,
		Middleware: []func(http.Handler) http.Handler{
			func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("X-Test", "1")
					next.ServeHTTP(w, r)
				})
			},
		},
		ExtraRoutes: func(m *http.ServeMux) {
			m.HandleFunc("GET /extra", func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("extra"))
			})
		},
	})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ping", nil))
	if rec.Code != 200 || rec.Body.String() != "pong" || rec.Header().Get("X-Test") != "1" {
		t.Fatalf("ping status=%d body=%q header=%q", rec.Code, rec.Body.String(), rec.Header().Get("X-Test"))
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/extra", nil))
	if rec.Code != 200 || rec.Body.String() != "extra" {
		t.Fatalf("extra status=%d body=%q", rec.Code, rec.Body.String())
	}
}
