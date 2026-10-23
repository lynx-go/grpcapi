// Package cors 提供 CORS（跨源资源共享）中间件。
//
// 定位：浏览器安全面的另一半——csrf 防跨站写，cors 管跨源读。默认
// fail-closed：未配置 AllowedOrigins 时不放行任何跨源请求（同源请求不受
// 影响）；origin 只接受精确匹配（scheme://host），不做子域通配或反射，
// 避免 origin 伪造与 credentials 组合放大。跨源的认证授权仍由 authn/authz
// 决定，CORS 只是浏览器读授权，不是服务端访问控制。
//
// 挂载：server.Config.CORS（全局），或 APIConfig.Middleware /
// HTTPMiddleware（按 API 面）。预检请求（OPTIONS + Access-Control-Request-
// Method）在本中间件短路，不会进入后续 handler。
package cors

import (
	"fmt"
	"net/http"
	"strings"
)

// Config 是 CORS 中间件配置；零值 = 不放行任何跨源请求。
type Config struct {
	// AllowedOrigins 是允许的 origin 精确列表（scheme://host，尾斜杠忽略，
	// 比较大小写不敏感）。"*" = 任意 origin（此时不得开启 AllowCredentials）。
	// 空 = 不放行任何跨源请求；同源请求与不带 Origin 的非浏览器客户端
	// 不受影响。
	AllowedOrigins []string
	// AllowedMethods 是预检允许的 HTTP 方法；nil = GET/HEAD/POST/PUT/PATCH/DELETE。
	AllowedMethods []string
	// AllowedHeaders 是预检允许的请求头（大小写不敏感）；nil = 与
	// gateway.HeaderPolicy 安全默认对齐（authorization/content-type/
	// x-api-key/x-request-id/idempotency-key/x-csrf-token/cookie）。
	// 不在列表中的请求头会让预检失败——项目专属头在此显式追加。
	AllowedHeaders []string
	// ExposedHeaders 是允许浏览器读取的响应头；默认无。
	ExposedHeaders []string
	// AllowCredentials 允许跨源请求携带 cookie/凭证；与 "*" 互斥。
	AllowCredentials bool
	// MaxAgeSeconds 是预检结果缓存时长（Access-Control-Max-Age）；0 = 不下发。
	MaxAgeSeconds int
}

func (c Config) normalize() Config {
	if len(c.AllowedMethods) == 0 {
		c.AllowedMethods = []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}
	}
	if c.AllowedHeaders == nil {
		c.AllowedHeaders = []string{
			"authorization", "content-type", "cookie",
			"x-api-key", "x-request-id", "idempotency-key", "x-csrf-token",
		}
	}
	out := Config{
		AllowedOrigins:   make([]string, len(c.AllowedOrigins)),
		AllowedMethods:   make([]string, len(c.AllowedMethods)),
		AllowedHeaders:   make([]string, len(c.AllowedHeaders)),
		ExposedHeaders:   make([]string, len(c.ExposedHeaders)),
		AllowCredentials: c.AllowCredentials,
		MaxAgeSeconds:    c.MaxAgeSeconds,
	}
	for i, o := range c.AllowedOrigins {
		out.AllowedOrigins[i] = strings.ToLower(strings.TrimRight(o, "/"))
	}
	for i, m := range c.AllowedMethods {
		out.AllowedMethods[i] = strings.ToUpper(m)
	}
	for i, h := range c.AllowedHeaders {
		out.AllowedHeaders[i] = strings.ToLower(h)
	}
	for i, h := range c.ExposedHeaders {
		out.ExposedHeaders[i] = strings.TrimSpace(h)
	}
	return out
}

// Middleware 是 CORS 中间件。
type Middleware struct {
	cfg Config
}

// New 构造 CORS 中间件；配置矛盾（"*" 与 credentials 同用）启动失败。
func New(cfg Config) (*Middleware, error) {
	cfg = cfg.normalize()
	for _, o := range cfg.AllowedOrigins {
		if o == "*" && cfg.AllowCredentials {
			return nil, fmt.Errorf("cors: AllowedOrigins \"*\" cannot be combined with AllowCredentials; list exact origins instead")
		}
	}
	return &Middleware{cfg: cfg}, nil
}

// Handler 包装 next。预检请求短路；实际请求按 origin 匹配结果补响应头。
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			// 非浏览器/同源请求：无 CORS 语义，原样放行。
			next.ServeHTTP(w, r)
			return
		}
		if !m.originAllowed(origin) {
			if isPreflight(r) {
				http.Error(w, "cors origin rejected", http.StatusForbidden)
				return
			}
			// 实际请求：不带 CORS 头继续（浏览器侧拦截读取；服务端是否
			// 处理由 authn/authz 决定，CORS 不是访问控制）。
			next.ServeHTTP(w, r)
			return
		}
		if isPreflight(r) {
			m.handlePreflight(w, r, origin)
			return
		}
		m.setCommonHeaders(w, origin)
		next.ServeHTTP(w, r)
	})
}

func (m *Middleware) originAllowed(origin string) bool {
	if len(m.cfg.AllowedOrigins) == 0 {
		return false
	}
	o := strings.ToLower(strings.TrimRight(origin, "/"))
	for _, allowed := range m.cfg.AllowedOrigins {
		if allowed == "*" || allowed == o {
			return true
		}
	}
	return false
}

func (m *Middleware) wildcard() bool {
	for _, o := range m.cfg.AllowedOrigins {
		if o == "*" {
			return true
		}
	}
	return false
}

func isPreflight(r *http.Request) bool {
	return r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != ""
}

func (m *Middleware) handlePreflight(w http.ResponseWriter, r *http.Request, origin string) {
	method := strings.ToUpper(r.Header.Get("Access-Control-Request-Method"))
	if !containsFold(m.cfg.AllowedMethods, method) {
		http.Error(w, "cors method rejected", http.StatusForbidden)
		return
	}
	// 逐个比对预检声明的请求头；缺失或不在允许列表即拒绝（fail-closed）。
	for _, h := range requestedHeaders(r) {
		if !containsFold(m.cfg.AllowedHeaders, h) {
			http.Error(w, "cors header rejected", http.StatusForbidden)
			return
		}
	}
	m.setCommonHeaders(w, origin)
	w.Header().Set("Access-Control-Allow-Methods", strings.Join(m.cfg.AllowedMethods, ", "))
	w.Header().Set("Access-Control-Allow-Headers", strings.Join(m.cfg.AllowedHeaders, ", "))
	if m.cfg.MaxAgeSeconds > 0 {
		w.Header().Set("Access-Control-Max-Age", fmt.Sprintf("%d", m.cfg.MaxAgeSeconds))
	}
	addVary(w, "Access-Control-Request-Method", "Access-Control-Request-Headers")
	w.WriteHeader(http.StatusNoContent)
}

func (m *Middleware) setCommonHeaders(w http.ResponseWriter, origin string) {
	if m.wildcard() && !m.cfg.AllowCredentials {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	} else {
		// 精确列表 + credentials：回显具体 origin，绝不回显 "*"。
		w.Header().Set("Access-Control-Allow-Origin", origin)
		addVary(w, "Origin")
	}
	if m.cfg.AllowCredentials {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}
	if len(m.cfg.ExposedHeaders) > 0 {
		w.Header().Set("Access-Control-Expose-Headers", strings.Join(m.cfg.ExposedHeaders, ", "))
	}
}

func requestedHeaders(r *http.Request) []string {
	raw := r.Header.Get("Access-Control-Request-Headers")
	if raw == "" {
		return nil
	}
	var out []string
	for _, h := range strings.Split(raw, ",") {
		if h = strings.TrimSpace(h); h != "" {
			out = append(out, strings.ToLower(h))
		}
	}
	return out
}

func containsFold(list []string, want string) bool {
	for _, v := range list {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}

func addVary(w http.ResponseWriter, values ...string) {
	existing := w.Header().Get("Vary")
	for _, v := range values {
		if !strings.Contains(existing, v) {
			existing = strings.Join(appendNonEmpty(existing, v), ", ")
		}
	}
	w.Header().Set("Vary", existing)
}

func appendNonEmpty(existing, v string) []string {
	if existing == "" {
		return []string{v}
	}
	return []string{existing, v}
}
