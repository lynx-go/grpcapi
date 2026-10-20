package csrf_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lynx-go/grpcapi/csrf"
)

func TestSafeMethodBypasses(t *testing.T) {
	m := csrf.New(csrf.Config{})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	m.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })).ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestUnsafeMethodRequiresMatchingToken(t *testing.T) {
	m := csrf.New(csrf.Config{})
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })

	rec := httptest.NewRecorder()
	m.Handler(next).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing token status = %d, want 403", rec.Code)
	}

	rec = httptest.NewRecorder()
	m.Issue(rec)
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %+v", cookies)
	}
	token := cookies[0].Value

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(cookies[0])
	req.Header.Set("X-CSRF-Token", token)
	rec = httptest.NewRecorder()
	m.Handler(next).ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("valid token status = %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(cookies[0])
	req.Header.Set("X-CSRF-Token", "wrong")
	rec = httptest.NewRecorder()
	m.Handler(next).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("mismatch status = %d, want 403", rec.Code)
	}
}

func TestOriginAllowlist(t *testing.T) {
	m := csrf.New(csrf.Config{AllowedOrigins: []string{"https://app.example.com"}})
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	rec := httptest.NewRecorder()
	m.Issue(rec)
	cookies := rec.Result().Cookies()

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(cookies[0])
	req.Header.Set("X-CSRF-Token", cookies[0].Value)
	req.Header.Set("Origin", "https://evil.example")
	rec = httptest.NewRecorder()
	m.Handler(next).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("bad origin status = %d, want 403", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(cookies[0])
	req.Header.Set("X-CSRF-Token", cookies[0].Value)
	req.Header.Set("Origin", "https://app.example.com")
	rec = httptest.NewRecorder()
	m.Handler(next).ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("good origin status = %d", rec.Code)
	}
}
