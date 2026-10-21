package gateway

import (
	"net/textproto"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
)

// HeaderPolicy 是 gateway 入/出站 header 策略。
type HeaderPolicy struct {
	// Deny 恒拒绝；nil = 默认 authorization + x-grpcapi-client-ip，空切片 = 不拒绝。
	Deny []string
	// Allow 直通为 metadata；nil = 默认 cookie/x-api-key/x-request-id/idempotency-key。
	Allow []string
	// Direct 出站直透；nil = 默认 set-cookie。
	Direct []string
	// FallbackIn 未命中时的默认 matcher。
	FallbackIn func(string) (string, bool)
	// FallbackOut 未命中时的默认 matcher。
	FallbackOut func(string) (string, bool)
}

func defaultDeniedHeaders() []string {
	return []string{
		"authorization",
		"grpcgateway-authorization",
		"grpc-metadata-authorization",
		"x-grpcapi-client-ip",
		"grpcgateway-x-grpcapi-client-ip",
		"grpc-metadata-x-grpcapi-client-ip",
	}
}

// DefaultHeaderPolicy 返回安全默认。
func DefaultHeaderPolicy() HeaderPolicy {
	return HeaderPolicy{
		Deny:   defaultDeniedHeaders(),
		Allow:  []string{"cookie", "x-api-key", "x-request-id", "idempotency-key"},
		Direct: []string{"set-cookie"},
	}
}

func (p HeaderPolicy) normalize() HeaderPolicy {
	if p.Deny == nil {
		p.Deny = defaultDeniedHeaders()
	}
	if p.Allow == nil {
		p.Allow = []string{"cookie", "x-api-key", "x-request-id", "idempotency-key"}
	}
	if p.Direct == nil {
		p.Direct = []string{"set-cookie"}
	}
	if p.FallbackIn == nil {
		p.FallbackIn = runtime.DefaultHeaderMatcher
	}
	if p.FallbackOut == nil {
		p.FallbackOut = func(key string) (string, bool) {
			return runtime.MetadataHeaderPrefix + key, true
		}
	}
	return p
}

func lowerSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, v := range values {
		out[strings.ToLower(strings.TrimSpace(v))] = struct{}{}
	}
	return out
}

// IncomingPolicy 构造入站 matcher。Deny 优先于 Allow。
func IncomingPolicy(p HeaderPolicy) func(string) (string, bool) {
	p = p.normalize()
	deny := lowerSet(p.Deny)
	allow := lowerSet(p.Allow)
	return func(key string) (string, bool) {
		lk := strings.ToLower(key)
		if _, blocked := deny[lk]; blocked {
			return "", false
		}
		if _, ok := allow[lk]; ok {
			return lk, true
		}
		return p.FallbackIn(key)
	}
}

// OutgoingPolicy 构造出站 matcher。Direct 优先；其余走 fallback（默认加前缀）。
func OutgoingPolicy(p HeaderPolicy) func(string) (string, bool) {
	p = p.normalize()
	direct := lowerSet(p.Direct)
	return func(key string) (string, bool) {
		lk := strings.ToLower(key)
		if _, ok := direct[lk]; ok {
			return textproto.CanonicalMIMEHeaderKey(key), true
		}
		return p.FallbackOut(key)
	}
}
