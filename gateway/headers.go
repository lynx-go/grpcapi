package gateway

import (
	"net/textproto"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
)

// IncomingMatcher 构造 grpc-gateway 入站 header matcher
// （平移自 torchwood authIncomingHeaderMatcher）：
//
//   - "authorization" 恒拒绝——grpc-gateway annotateContext 对 Authorization 头
//     有内置向后兼容透传（无前缀 metadata "authorization"）；matcher 再放行会导致
//     同值被 append 两次，服务端多凭证判定直接 401，所有 Bearer 认证请求不可用
//     （“双写 401”坑）；
//   - cookie / x-api-key / x-request-id / idempotency-key 放行（键名规整为小写
//     metadata 键，便于服务端统一读取）；
//   - extraAllow 追加项目专属放行头（如 x-torchwood-project）；
//   - 其余回落 grpc-gateway 默认行为：Grpc-Metadata- 前缀与标准 HTTP 头透传为
//     metadata，普通自定义头拒绝。
func IncomingMatcher(extraAllow ...string) func(string) (string, bool) {
	allowed := map[string]struct{}{
		"cookie":          {},
		"x-api-key":       {},
		"x-request-id":    {},
		"idempotency-key": {},
	}
	for _, k := range extraAllow {
		allowed[strings.ToLower(k)] = struct{}{}
	}
	return func(key string) (string, bool) {
		lk := strings.ToLower(key)
		if lk == "authorization" {
			// 见函数注释：放行即双写 401，恒拒绝。
			return "", false
		}
		if _, ok := allowed[lk]; ok {
			return lk, true
		}
		return runtime.DefaultHeaderMatcher(key)
	}
}

// OutgoingMatcher 构造 grpc-gateway 出站 header matcher
// （平移自 torchwood authOutgoingHeaderMatcher）：
//
//   - set-cookie 直透为 Set-Cookie 响应头（grpc-gateway 默认给所有 metadata 加
//     "Grpc-Metadata-" 前缀，不自定义 matcher 则 HttpOnly 会话 cookie 永远到不了
//     浏览器）；
//   - direct 追加项目专属直透头（如幂等重放标记 x-torchwood-replayed）；
//   - 其余 key 保持默认行为：加 "Grpc-Metadata-" 前缀。
func OutgoingMatcher(direct ...string) func(string) (string, bool) {
	directSet := map[string]struct{}{"set-cookie": {}}
	for _, k := range direct {
		directSet[strings.ToLower(k)] = struct{}{}
	}
	return func(key string) (string, bool) {
		if _, ok := directSet[strings.ToLower(key)]; ok {
			return textproto.CanonicalMIMEHeaderKey(key), true
		}
		return runtime.MetadataHeaderPrefix + key, true
	}
}
