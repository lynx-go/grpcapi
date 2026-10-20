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
	TLS        *tls.ConnectionState
	HTTP       *http.Request
}

// Empty 报告是否没有任何待认证凭证。
func (c Credentials) Empty() bool {
	return len(c.Bearer) == 0 && len(c.APIKeys) == 0 && len(c.Cookies) == 0
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

// AuthKinds 返回出现的凭证种类数（Bearer/API key/Cookie）。
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
	if token, ok := bearerToken(r.Header.Get("Authorization")); ok {
		c.Bearer = append(c.Bearer, token)
	}
	if v := r.Header.Get("X-API-Key"); v != "" {
		c.APIKeys = append(c.APIKeys, v)
	}
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
