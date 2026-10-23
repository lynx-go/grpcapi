// Package authn 定义认证 SPI：把请求凭证变成 principal.Principal。
//
// 库不绑定 JWT/session/API key 的具体实现；参考实现在 authn/jwt、
// authn/session、authn/apikey，authn/admin 负责认证后的角色增强。
package authn

import (
	"context"
	"crypto/tls"
	"net/http"
	"strings"

	"github.com/lynx-go/grpcapi/principal"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// Credentials 是一次请求的凭证投影。
type Credentials struct {
	FullMethod string
	Metadata   metadata.MD
	Peer       *peer.Peer
	Bearer     []string
	APIKeys    []string
	Cookies    []string
	// Tickets 是短时单用途票据（EventSource/浏览器 WebSocket 无法带自定义
	// header 的场景，经 URL query 传递）。HTTP 侧需显式组合 WithQueryTicket
	// 提取；gRPC 侧从 x-ticket metadata 提取（gateway 项目可经 MuxOptions.
	// Metadata 把 query 参数转发为该键）。
	Tickets []string
	TLS     *tls.ConnectionState
	HTTP    *http.Request
}

// CredentialKind 是凭证族标识，用于按凭证类型配置策略。
type CredentialKind string

const (
	KindBearer     CredentialKind = "bearer"
	KindAPIKey     CredentialKind = "api_key"
	KindCookie     CredentialKind = "cookie"
	KindClientCert CredentialKind = "client_cert"
	KindTicket     CredentialKind = "ticket"
)

// Empty 报告是否没有任何待认证凭证。
func (c Credentials) Empty() bool {
	return len(c.Bearer) == 0 && len(c.APIKeys) == 0 && len(c.Cookies) == 0 && len(c.Tickets) == 0 && !c.HasClientCert()
}

// HasClientCert 报告是否带 mTLS 客户端证书。
func (c Credentials) HasClientCert() bool {
	return c.TLS != nil && len(c.TLS.PeerCertificates) > 0
}

// BearerToken 返回第一个 Bearer token。
func (c Credentials) BearerToken() string {
	if len(c.Bearer) == 0 {
		return ""
	}
	return c.Bearer[0]
}

// APIKey 返回第一个 API key。
func (c Credentials) APIKey() string {
	if len(c.APIKeys) == 0 {
		return ""
	}
	return c.APIKeys[0]
}

// Ticket 返回第一个票据。
func (c Credentials) Ticket() string {
	if len(c.Tickets) == 0 {
		return ""
	}
	return c.Tickets[0]
}

// PresentedKinds 返回请求携带的凭证族（多凭证时按固定顺序）。
func (c Credentials) PresentedKinds() []CredentialKind {
	var out []CredentialKind
	if len(c.Bearer) > 0 {
		out = append(out, KindBearer)
	}
	if len(c.APIKeys) > 0 {
		out = append(out, KindAPIKey)
	}
	if len(c.Cookies) > 0 {
		out = append(out, KindCookie)
	}
	if len(c.Tickets) > 0 {
		out = append(out, KindTicket)
	}
	if c.HasClientCert() {
		out = append(out, KindClientCert)
	}
	return out
}

// Cookie 返回指定 cookie 值；多个 Cookie 头会被解析。
func (c Credentials) Cookie(name string) string {
	for _, raw := range c.Cookies {
		req := &http.Request{Header: http.Header{"Cookie": []string{raw}}}
		for _, ck := range req.Cookies() {
			if ck.Name == name {
				return ck.Value
			}
		}
	}
	return ""
}

// AuthKinds 返回出现的凭证种类数（Bearer/API key/Cookie/票据/mTLS）。
func (c Credentials) AuthKinds() int {
	n := 0
	if len(c.Bearer) > 0 {
		n++
	}
	if len(c.APIKeys) > 0 {
		n++
	}
	if len(c.Cookies) > 0 {
		n++
	}
	if len(c.Tickets) > 0 {
		n++
	}
	if c.HasClientCert() {
		n++
	}
	return n
}

// Authenticator 把一个凭证族转成 Principal。
//
// (nil, nil) = 不认识这种凭证，继续尝试下一个；
// (nil, err) = 认识但拒绝/后端故障，立即返回。
type Authenticator interface {
	Name() string
	Authenticate(ctx context.Context, c Credentials) (*principal.Principal, error)
}

// Chain 按顺序尝试认证器。
type Chain []Authenticator

// Authenticate 依次尝试；首个返回 Principal 的认证器胜出。
func (c Chain) Authenticate(ctx context.Context, creds Credentials) (*principal.Principal, error) {
	for _, a := range c {
		if a == nil {
			continue
		}
		p, err := a.Authenticate(ctx, creds)
		if err != nil {
			return nil, err
		}
		if p != nil {
			return p, nil
		}
	}
	return nil, nil
}

// Enricher 在认证成功后补充 Principal（如 admin store 角色）。
type Enricher interface {
	Name() string
	Enrich(ctx context.Context, p *principal.Principal) error
}

// Extractor 从 gRPC metadata/peer 提取凭证。
type Extractor interface {
	Extract(ctx context.Context, fullMethod string, md metadata.MD, peer *peer.Peer) (Credentials, error)
}

// HTTPExtractor 从 HTTP 请求提取凭证。
type HTTPExtractor interface {
	ExtractHTTP(ctx context.Context, fullMethod string, r *http.Request) (Credentials, error)
}

// DefaultExtractor 提取 authorization(Bearer)、x-api-key、cookie、TLS 状态。
func DefaultExtractor() Extractor { return defaultExtractor{} }

type defaultExtractor struct{}

func (defaultExtractor) Extract(_ context.Context, fullMethod string, md metadata.MD, p *peer.Peer) (Credentials, error) {
	c := Credentials{FullMethod: fullMethod, Metadata: md, Peer: p}
	for _, v := range md.Get("authorization") {
		if token, ok := bearerToken(v); ok {
			c.Bearer = append(c.Bearer, token)
		}
	}
	c.APIKeys = append(c.APIKeys, md.Get("x-api-key")...)
	c.Cookies = append(c.Cookies, md.Get("cookie")...)
	c.Tickets = append(c.Tickets, md.Get("x-ticket")...)
	if p != nil && p.AuthInfo != nil {
		switch info := p.AuthInfo.(type) {
		case credentials.TLSInfo:
			state := info.State
			c.TLS = &state
		case *credentials.TLSInfo:
			if info != nil {
				state := info.State
				c.TLS = &state
			}
		}
	}
	return c, nil
}

// DefaultHTTPExtractor 提取 Authorization(Bearer)、X-API-Key、Cookie。
func DefaultHTTPExtractor() HTTPExtractor { return defaultHTTPExtractor{} }

type defaultHTTPExtractor struct{}

func (defaultHTTPExtractor) ExtractHTTP(_ context.Context, fullMethod string, r *http.Request) (Credentials, error) {
	c := Credentials{FullMethod: fullMethod, HTTP: r}
	for _, value := range r.Header.Values("Authorization") {
		if token, ok := bearerToken(value); ok {
			c.Bearer = append(c.Bearer, token)
		}
	}
	c.APIKeys = append(c.APIKeys, r.Header.Values("X-API-Key")...)
	c.Cookies = append(c.Cookies, r.Header.Values("Cookie")...)
	if r.TLS != nil {
		c.TLS = r.TLS
	}
	return c, nil
}

func bearerToken(header string) (string, bool) {
	header = strings.TrimSpace(header)
	if header == "" {
		return "", false
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", false
	}
	return token, true
}

// WithQueryTicket 组合一个从 URL query 参数提取短时票据的 HTTP 提取器。
//
// 默认提取器不从 query 取凭证——query 会进代理/访问日志，泄露面远大于
// header；只有浏览器技术限制（EventSource/WebSocket 无法带自定义 header）
// 才值得付出这个代价，因此必须显式开启。约定：
//
//   - 票据必须短 TTL + 单用途（兑换即作废），由 Store 侧保证；
//   - param 为空时用 "ticket"；重复出现同名参数视为多个凭证，按多凭证
//     规则被拒绝；
//   - proto 路由（经 gateway 转发 gRPC）需要票据时，项目用 MuxOptions.
//     Metadata 把 query 参数转发为 "x-ticket" metadata，gRPC 侧默认提取器
//     即可读出。
func WithQueryTicket(param string, next HTTPExtractor) HTTPExtractor {
	if param == "" {
		param = "ticket"
	}
	if next == nil {
		next = DefaultHTTPExtractor()
	}
	return queryTicketExtractor{param: param, next: next}
}

type queryTicketExtractor struct {
	param string
	next  HTTPExtractor
}

func (e queryTicketExtractor) ExtractHTTP(ctx context.Context, fullMethod string, r *http.Request) (Credentials, error) {
	c, err := e.next.ExtractHTTP(ctx, fullMethod, r)
	if err != nil {
		return c, err
	}
	// 只在 URL query 上取，不碰 body；空值不算凭证。
	for _, v := range r.URL.Query()[e.param] {
		if v != "" {
			c.Tickets = append(c.Tickets, v)
		}
	}
	return c, nil
}
