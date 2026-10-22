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

func TestExempt(t *testing.T) {
	m := csrf.New(csrf.Config{Exempt: func(r *http.Request) bool {
		return r.URL.Path == "/webhook"
	}})
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	rec := httptest.NewRecorder()
	m.Handler(next).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/webhook", nil))
	if rec.Code != 200 {
		t.Fatalf("exempt status = %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	m.Handler(next).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/other", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-exempt status = %d, want 403", rec.Code)
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

func TestEmptyAllowlistSameOriginOnly(t *testing.T) {
	// 空允许列表 = 仅同源：跨站 Origin 拒绝（原为完全跳过校验的不安全
	// 默认），同源放行，缺失 Origin/Referer 的非浏览器客户端交由 token
	// 比对防线。
	m := csrf.New(csrf.Config{})
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	run := func(origin string) int {
		rec := httptest.NewRecorder()
		m.Issue(rec)
		cookie := rec.Result().Cookies()[0]
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Host = "api.example.com"
		req.AddCookie(cookie)
		req.Header.Set("X-CSRF-Token", cookie.Value)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		rec = httptest.NewRecorder()
		m.Handler(next).ServeHTTP(rec, req)
		return rec.Code
	}

	if got := run("https://evil.example"); got != http.StatusForbidden {
		t.Fatalf("cross-origin status = %d, want 403", got)
	}
	if got := run("https://api.example.com"); got != 200 {
		t.Fatalf("same-origin status = %d, want 200", got)
	}
	if got := run("http://api.example.com:8080"); got != http.StatusForbidden {
		t.Fatalf("same-host different port status = %d, want 403", got)
	}
	if got := run(""); got != 200 {
		t.Fatalf("no origin (non-browser) status = %d, want 200 (token check still applies)", got)
	}

	// 缺失 Origin/Referer 时 token 校验依然生效。
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Host = "api.example.com"
	rec := httptest.NewRecorder()
	m.Handler(next).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing token status = %d, want 403", rec.Code)
	}
}

func TestInsecureCookieOptOut(t *testing.T) {
	// cookie 默认恒带 Secure；显式 InsecureCookie 才允许非 HTTPS（本地开发）。
	rec := httptest.NewRecorder()
	csrf.New(csrf.Config{}).Issue(rec)
	if !rec.Result().Cookies()[0].Secure {
		t.Fatal("csrf cookie must be Secure by default")
	}
	rec = httptest.NewRecorder()
	csrf.New(csrf.Config{InsecureCookie: true}).Issue(rec)
	if rec.Result().Cookies()[0].Secure {
		t.Fatal("InsecureCookie opt-out must drop Secure")
	}
}
