package gateway

import (
	"net/textproto"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
)

// HeaderPolicy 是 gateway 入/出站 header 策略，是 header 行为的唯一事实源：
//
//   - Deny 恒拒绝。"authorization" 系列在内置默认里恒拒——grpc-gateway
//     annotateContext 对 Authorization 头有内置向后兼容透传（无前缀 metadata
//     "authorization"）；matcher 再放行会导致同值被 append 两次，服务端多凭证
//     判定直接 401，所有 Bearer 认证请求不可用（"双写 401"坑）。
//     "x-grpcapi-client-ip" 系列同样恒拒——它是 server 注入的内部可信头，
//     放行等于允许客户端伪造 client-ip。
//   - Allow 直通为 metadata（键名规整为小写，便于服务端统一读取）：内置默认
//     cookie / x-api-key / x-request-id / idempotency-key。
//   - Direct 出站直透（不再加 "Grpc-Metadata-" 前缀）：内置默认 set-cookie——
//     grpc-gateway 默认给所有 metadata 加前缀，不自定义则 HttpOnly 会话 cookie
//     永远到不了浏览器。
//   - 未命中的 key 走 Fallback：入站默认 runtime.DefaultHeaderMatcher
//     （Grpc-Metadata- 前缀与标准 HTTP 头透传为 metadata，普通自定义头拒绝），
//     出站默认加 "Grpc-Metadata-" 前缀。
//
// nil 字段取内置默认；空切片表示显式清空（不放行/不直透任何头）。
type HeaderPolicy struct {
	// Deny 恒拒绝；nil = 默认 authorization + x-grpcapi-client-ip 系列，空切片 = 不拒绝。
	Deny []string
	// Allow 直通为 metadata；nil = 默认 cookie/x-api-key/x-request-id/idempotency-key。
	Allow []string
	// Direct 出站直透；nil = 默认 set-cookie。
	Direct []string
	// FallbackIn 未命中时的默认入站 matcher。
	FallbackIn func(string) (string, bool)
	// FallbackOut 未命中时的默认出站 matcher。
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
