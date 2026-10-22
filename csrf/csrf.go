// Package csrf 提供 double-submit cookie 形式的 CSRF 中间件。
//
// 约定：登录时调用 Issue 设置 CSRF cookie（JS 可读），前端在 unsafe
// 请求中把同一 token 放到 header；中间件比对 cookie/header，并可选校验
// Origin/Referer 允许列表。
package csrf

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Config 是 CSRF 中间件配置。
type Config struct {
	// CookieName 默认 "csrf_token"。
	CookieName string
	// HeaderName 默认 "X-CSRF-Token"。
	HeaderName string
	// CookiePath 默认 "/"。
	CookiePath string
	// InsecureCookie 显式允许在非 HTTPS 环境下发 cookie（本地开发）。
	// 默认 false = cookie 恒带 Secure。
	InsecureCookie bool
	// SameSite 默认 Lax。
	SameSite http.SameSite
	// AllowedOrigins 校验 Origin/Referer 的来源。非空 = 严格允许列表
	// （无 Origin/Referer 的 unsafe 请求也拒绝，非浏览器客户端请用
	// Exempt 放行）；空 = 仅同源（Origin/Referer 的 host 必须与请求
	// Host 一致，缺失时交由 token 比对防线）。此前空列表完全跳过来源
	// 校验的不安全默认已移除。
	AllowedOrigins []string
	// Exempt 返回 true 时跳过该请求的 CSRF 校验（如使用独立凭证的 webhook）。
	// 默认 nil = 所有 unsafe 请求都校验。
	Exempt func(*http.Request) bool
}

func (c Config) normalize() Config {
	if c.CookieName == "" {
		c.CookieName = "csrf_token"
	}
	if c.HeaderName == "" {
		c.HeaderName = "X-CSRF-Token"
	}
	if c.CookiePath == "" {
		c.CookiePath = "/"
	}
	if c.SameSite == 0 {
		c.SameSite = http.SameSiteLaxMode
	}
	return c
}

// Middleware 是 CSRF 校验中间件。
type Middleware struct {
	cfg Config
}

// New 构造 CSRF 中间件。
func New(cfg Config) *Middleware {
	return &Middleware{cfg: cfg.normalize()}
}

// Issue 生成并设置 CSRF cookie，返回 token；登录成功后调用。
func (m *Middleware) Issue(w http.ResponseWriter) (string, error) {
	token, err := newToken()
	if err != nil {
		return "", err
	}
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure 恒 true（除非显式 InsecureCookie）；HttpOnly 必须 false（前端需读 token 回写 header）
		Name:     m.cfg.CookieName,
		Value:    token,
		Path:     m.cfg.CookiePath,
		Secure:   !m.cfg.InsecureCookie,
		SameSite: m.cfg.SameSite,
		HttpOnly: false, // 前端必须可读，才能写入 header
	})
	return token, nil
}

// Handler 包装 next。
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
			next.ServeHTTP(w, r)
			return
		}
		if m.cfg.Exempt != nil && m.cfg.Exempt(r) {
			next.ServeHTTP(w, r)
			return
		}
		if !m.originAllowed(r) {
			http.Error(w, "csrf origin rejected", http.StatusForbidden)
			return
		}
		cookie, err := r.Cookie(m.cfg.CookieName)
		if err != nil || cookie.Value == "" {
			http.Error(w, "csrf token missing", http.StatusForbidden)
			return
		}
		header := r.Header.Get(m.cfg.HeaderName)
		if header == "" || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(header)) != 1 {
			http.Error(w, "csrf token mismatch", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (m *Middleware) originAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = r.Header.Get("Referer")
	}
	if len(m.cfg.AllowedOrigins) == 0 {
		// 未配置允许列表 = 仅同源：跨站 unsafe 请求浏览器必带 Origin，
		// host 与请求 Host 不同即拒绝；非浏览器客户端不带 Origin/
		// Referer，交由 token 比对防线（host 比对足够覆盖 CSRF 威胁，
		// 方案在 TLS 终结之后拿不到可靠 scheme）。
		if origin == "" {
			return true
		}
		u, err := url.Parse(origin)
		if err != nil {
			return false
		}
		return strings.EqualFold(u.Host, r.Host)
	}
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	got := u.Scheme + "://" + u.Host
	for _, allowed := range m.cfg.AllowedOrigins {
		if strings.EqualFold(strings.TrimRight(allowed, "/"), got) {
			return true
		}
	}
	return false
}

func newToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("csrf: random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
