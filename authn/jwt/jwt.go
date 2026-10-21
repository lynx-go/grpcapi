// Package jwt 提供 JWT/OIDC 认证参考实现。
//
// 默认只做 token 校验与 claims→Principal 映射；JWKS 拉取/缓存由 JWKS
// helper 提供。项目可以注入自定义 Verifier 或 Claims 映射。
package jwt

import (
	"context"
	"fmt"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/lynx-go/grpcapi/authn"
	"github.com/lynx-go/grpcapi/principal"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Claims 是 JWT claims 的只读视图。
type Claims map[string]any

// String 返回字符串 claim。
func (c Claims) String(key string) string {
	v, _ := c[key].(string)
	return v
}

// Strings 返回字符串切片 claim（兼容 []any/[]string/单字符串）。
func (c Claims) Strings(key string) []string {
	switch v := c[key].(type) {
	case []string:
		return append([]string(nil), v...)
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	default:
		return nil
	}
}

// Subject 返回 sub；缺失时回退 uid/user_id/id。
func (c Claims) Subject() string {
	for _, key := range []string{"sub", "uid", "user_id", "id"} {
		if v := c.String(key); v != "" {
			return v
		}
	}
	return ""
}

// Verifier 校验 token 并返回 claims。
type Verifier interface {
	Verify(ctx context.Context, token string) (Claims, error)
}

// Config 是 JWT 认证器配置。
type Config struct {
	// Verifier 与 (KeyFunc+Issuer/Audience) 二选一；Verifier 优先。
	Verifier Verifier
	KeyFunc  jwtlib.Keyfunc
	Issuer   string
	Audience string

	ClockSkew    time.Duration
	ValidMethods []string
	// AllowMissingExpiration 默认 false：必须带 exp，避免永不过期 token。
	AllowMissingExpiration bool

	// Claims 可选覆盖默认 claims→Principal 映射。
	Claims func(Claims) (*principal.Principal, error)
	// Kind 默认 "user"。
	Kind string
}

// Authenticator 实现 authn.Authenticator。
type Authenticator struct {
	verifier Verifier
	claims   func(Claims) (*principal.Principal, error)
	kind     string
}

// New 构造 JWT 认证器。
func New(cfg Config) (*Authenticator, error) {
	verifier := cfg.Verifier
	if verifier == nil {
		if cfg.KeyFunc == nil {
			return nil, fmt.Errorf("jwt: Verifier or KeyFunc is required")
		}
		methods := cfg.ValidMethods
		if len(methods) == 0 {
			methods = []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}
		}
		verifier = &Parser{
			KeyFunc:                cfg.KeyFunc,
			Issuer:                 cfg.Issuer,
			Audience:               cfg.Audience,
			ClockSkew:              cfg.ClockSkew,
			ValidMethods:           methods,
			AllowMissingExpiration: cfg.AllowMissingExpiration,
		}
	}
	kind := cfg.Kind
	if kind == "" {
		kind = principal.KindUser
	}
	return &Authenticator{verifier: verifier, claims: cfg.Claims, kind: kind}, nil
}

// Name 实现 authn.Authenticator。
func (a *Authenticator) Name() string { return "jwt" }

// Authenticate 实现 authn.Authenticator。
func (a *Authenticator) Authenticate(ctx context.Context, c authn.Credentials) (*principal.Principal, error) {
	token := c.BearerToken()
	if token == "" {
		return nil, nil
	}
	claims, err := a.verifier.Verify(ctx, token)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			return nil, st.Err()
		}
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}
	if a.claims != nil {
		p, err := a.claims(claims)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid token claims")
		}
		if p == nil {
			return nil, status.Error(codes.Unauthenticated, "invalid token claims")
		}
		return p, nil
	}
	id := claims.Subject()
	if id == "" {
		return nil, status.Error(codes.Unauthenticated, "token subject is missing")
	}
	// kind 只由服务端配置决定，不采信 token 的 kind claim——共享 IdP 下
	// 用户可影响的 claim 一旦能切换 principal kind 就是提权面。多 kind
	// 场景部署多个不同 Kind/issuer 的 Authenticator。
	kind := a.kind
	p := &principal.Principal{
		ID:     id,
		Kind:   kind,
		Claims: map[string][]string{},
		Attrs:  map[string]string{},
		Raw:    claims,
	}
	multi := map[string]struct{}{
		"roles": {}, "scopes": {}, "permissions": {}, "admin_roles": {},
		"tenant": {}, "aud": {},
	}
	for key, value := range claims {
		switch v := value.(type) {
		case []any, []string:
			if vs := claims.Strings(key); len(vs) > 0 {
				p.Claims[key] = vs
			}
		case string:
			if _, ok := multi[key]; ok {
				p.Claims[key] = []string{v}
			} else if key != "sub" {
				p.Attrs[key] = v
			}
		}
	}
	if len(p.Claims) == 0 {
		p.Claims = nil
	}
	if len(p.Attrs) == 0 {
		p.Attrs = nil
	}
	return p, nil
}

// Parser 是基于 golang-jwt 的默认 Verifier。
type Parser struct {
	KeyFunc                jwtlib.Keyfunc
	Issuer                 string
	Audience               string
	ClockSkew              time.Duration
	ValidMethods           []string
	AllowMissingExpiration bool
}

// Verify 实现 Verifier。
func (p *Parser) Verify(_ context.Context, token string) (Claims, error) {
	options := []jwtlib.ParserOption{
		jwtlib.WithValidMethods(p.ValidMethods),
		jwtlib.WithLeeway(p.ClockSkew),
	}
	if p.Issuer != "" {
		options = append(options, jwtlib.WithIssuer(p.Issuer))
	}
	if p.Audience != "" {
		options = append(options, jwtlib.WithAudience(p.Audience))
	}
	if !p.AllowMissingExpiration {
		options = append(options, jwtlib.WithExpirationRequired())
	}
	parsed, err := jwtlib.ParseWithClaims(token, jwtlib.MapClaims{}, p.KeyFunc, options...)
	if err != nil {
		// JWKS/网络故障等显式 status 原样透传；token 本身的问题统一 401。
		if st, ok := status.FromError(err); ok && st.Code() != codes.Unauthenticated && st.Code() != codes.OK {
			return nil, st.Err()
		}
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}
	claims, ok := parsed.Claims.(jwtlib.MapClaims)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "invalid token claims")
	}
	return Claims(claims), nil
}

var _ authn.Authenticator = (*Authenticator)(nil)
var _ Verifier = (*Parser)(nil)
