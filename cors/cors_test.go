package cors_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lynx-go/grpcapi/cors"
)

func echoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func do(m *cors.Middleware, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	m.Handler(echoHandler()).ServeHTTP(w, r)
	return w
}

func TestCorsNoOriginPassesThrough(t *testing.T) {
	m, err := cors.New(cors.Config{AllowedOrigins: []string{"https://app.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	resp := do(m, httptest.NewRequest(http.MethodGet, "/v1/notes", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", resp.Code)
	}
	if got := resp.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("ACAO = %q, want empty for same-origin request", got)
	}
}

func TestCorsEmptyConfigAllowsNothing(t *testing.T) {
	m, err := cors.New(cors.Config{})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/v1/notes", nil)
	r.Header.Set("Origin", "https://evil.example.com")
	resp := do(m, r)
	if resp.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200 (actual request continues without headers)", resp.Code)
	}
	if got := resp.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("ACAO = %q, want empty for unconfigured origins", got)
	}
}

func TestCorsAllowedOriginActualRequest(t *testing.T) {
	m, err := cors.New(cors.Config{
		AllowedOrigins:   []string{"https://app.example.com/"},
		AllowCredentials: true,
		ExposedHeaders:   []string{"X-Request-Id"},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/v1/notes", nil)
	r.Header.Set("Origin", "https://APP.example.com")
	resp := do(m, r)
	if resp.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", resp.Code)
	}
	if got := resp.Header().Get("Access-Control-Allow-Origin"); got != "https://APP.example.com" {
		t.Fatalf("ACAO = %q, want echoed origin", got)
	}
	if got := resp.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("ACAC = %q, want true", got)
	}
	if got := resp.Header().Get("Access-Control-Expose-Headers"); got != "X-Request-Id" {
		t.Fatalf("ACAH(expose) = %q, want X-Request-Id", got)
	}
	if got := resp.Header().Get("Vary"); got != "Origin" {
		t.Fatalf("Vary = %q, want Origin", got)
	}
}

func TestCorsDisallowedOriginActualRequestContinuesWithoutHeaders(t *testing.T) {
	m, err := cors.New(cors.Config{AllowedOrigins: []string{"https://app.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/v1/notes", nil)
	r.Header.Set("Origin", "https://evil.example.com")
	resp := do(m, r)
	if resp.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200 (server still processes; browser blocks read)", resp.Code)
	}
	if got := resp.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("ACAO = %q, want empty", got)
	}
}

func TestCorsPreflightAllowed(t *testing.T) {
	m, err := cors.New(cors.Config{
		AllowedOrigins: []string{"https://app.example.com"},
		MaxAgeSeconds:  600,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodOptions, "/v1/notes", nil)
	r.Header.Set("Origin", "https://app.example.com")
	r.Header.Set("Access-Control-Request-Method", "POST")
	r.Header.Set("Access-Control-Request-Headers", "Content-Type, X-Api-Key")
	resp := do(m, r)
	if resp.Code != http.StatusNoContent {
		t.Fatalf("code = %d, want 204", resp.Code)
	}
	if got := resp.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Fatalf("ACAO = %q", got)
	}
	if got := resp.Header().Get("Access-Control-Allow-Methods"); got == "" {
		t.Fatal("ACAM missing")
	}
	if got := resp.Header().Get("Access-Control-Allow-Headers"); got == "" {
		t.Fatal("ACAH missing")
	}
	if got := resp.Header().Get("Access-Control-Max-Age"); got != "600" {
		t.Fatalf("Max-Age = %q, want 600", got)
	}
	if resp.Body.Len() != 0 {
		t.Fatalf("preflight body = %q, want empty", resp.Body.String())
	}
}

func TestCorsPreflightRejected(t *testing.T) {
	m, err := cors.New(cors.Config{AllowedOrigins: []string{"https://app.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		origin  string
		method  string
		headers string
	}{
		{"disallowed origin", "https://evil.example.com", "GET", ""},
		{"disallowed method", "https://app.example.com", "TRACE", ""},
		{"disallowed header", "https://app.example.com", "POST", "X-Evil-Header"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodOptions, "/v1/notes", nil)
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Access-Control-Request-Method", tc.method)
			if tc.headers != "" {
				r.Header.Set("Access-Control-Request-Headers", tc.headers)
			}
			resp := do(m, r)
			if resp.Code != http.StatusForbidden {
				t.Fatalf("code = %d, want 403", resp.Code)
			}
		})
	}
}

func TestCorsWildcardWithoutCredentials(t *testing.T) {
	m, err := cors.New(cors.Config{AllowedOrigins: []string{"*"}})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/v1/notes", nil)
	r.Header.Set("Origin", "https://any.example.com")
	resp := do(m, r)
	if got := resp.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("ACAO = %q, want *", got)
	}
}

func TestCorsWildcardWithCredentialsRejected(t *testing.T) {
	if _, err := cors.New(cors.Config{AllowedOrigins: []string{"*"}, AllowCredentials: true}); err == nil {
		t.Fatal("want error for wildcard + credentials")
	}
}

func TestCorsCustomAllowedHeaders(t *testing.T) {
	m, err := cors.New(cors.Config{
		AllowedOrigins: []string{"https://app.example.com"},
		AllowedHeaders: []string{"Content-Type", "X-Torchwood-Project"},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodOptions, "/v1/notes", nil)
	r.Header.Set("Origin", "https://app.example.com")
	r.Header.Set("Access-Control-Request-Method", "POST")
	r.Header.Set("Access-Control-Request-Headers", "x-torchwood-project")
	resp := do(m, r)
	if resp.Code != http.StatusNoContent {
		t.Fatalf("code = %d, want 204", resp.Code)
	}
}
