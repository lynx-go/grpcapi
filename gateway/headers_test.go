package gateway

import (
	"testing"
)

func TestIncomingPolicy(t *testing.T) {
	cases := []struct {
		name      string
		policy    HeaderPolicy
		key       string
		wantKey   string
		wantAllow bool
	}{
		// authorization 恒拒绝：matcher 放行会与 grpc-gateway 内置透传双写，
		// 服务端多凭证判定 401。
		{"authorization 拒绝", DefaultHeaderPolicy(), "Authorization", "", false},
		{"authorization 小写拒绝", DefaultHeaderPolicy(), "authorization", "", false},
		{"grpc-metadata-authorization 拒绝", DefaultHeaderPolicy(), "Grpc-Metadata-Authorization", "", false},
		{"grpcgateway-authorization 拒绝", DefaultHeaderPolicy(), "Grpcgateway-Authorization", "", false},
		{"client-ip 拒绝", DefaultHeaderPolicy(), "X-Grpcapi-Client-Ip", "", false},
		{"grpc-metadata-client-ip 拒绝", DefaultHeaderPolicy(), "Grpc-Metadata-X-Grpcapi-Client-Ip", "", false},
		{"cookie 放行", DefaultHeaderPolicy(), "Cookie", "cookie", true},
		{"cookie 小写放行", DefaultHeaderPolicy(), "cookie", "cookie", true},
		{"x-api-key 放行", DefaultHeaderPolicy(), "X-Api-Key", "x-api-key", true},
		{"x-request-id 放行", DefaultHeaderPolicy(), "X-Request-Id", "x-request-id", true},
		{"idempotency-key 放行", DefaultHeaderPolicy(), "Idempotency-Key", "idempotency-key", true},
		{"普通自定义头拒绝", DefaultHeaderPolicy(), "X-Custom", "", false},
		{"grpc 系统头保留", DefaultHeaderPolicy(), "Grpc-Metadata-Foo", "Foo", true},
		{"标准头默认透传", DefaultHeaderPolicy(), "Accept-Language", "grpcgateway-Accept-Language", true},
		{"零值等效默认", HeaderPolicy{}, "Cookie", "cookie", true},
		{"项目头 Allow 命中", HeaderPolicy{Allow: []string{"x-project"}}, "X-Project", "x-project", true},
		{"项目头未命中拒绝", HeaderPolicy{Allow: []string{"x-project"}}, "X-Other", "", false},
		// Cookie 是标准 HTTP 头：显式 Allow 未收录时仍走 DefaultHeaderMatcher
		// 回落透传（带 grpcgateway- 前缀），与 v2 行为一致。
		{"显式 Allow 未含标准头走回落", HeaderPolicy{Allow: []string{"x-project"}}, "Cookie", "grpcgateway-Cookie", true},
		{"Deny 优先于 Allow 与回落", HeaderPolicy{Deny: []string{"cookie"}}, "Cookie", "", false},
	}
	for _, tc := range cases {
		m := IncomingPolicy(tc.policy)
		got, ok := m(tc.key)
		if ok != tc.wantAllow || (ok && got != tc.wantKey) {
			t.Errorf("%s: IncomingPolicy(%+v)(%q) = (%q, %v), want (%q, %v)",
				tc.name, tc.policy, tc.key, got, ok, tc.wantKey, tc.wantAllow)
		}
	}
}

func TestOutgoingPolicy(t *testing.T) {
	cases := []struct {
		name    string
		policy  HeaderPolicy
		key     string
		wantKey string
	}{
		{"set-cookie 直透", DefaultHeaderPolicy(), "set-cookie", "Set-Cookie"},
		{"set-cookie 大小写不敏感", DefaultHeaderPolicy(), "Set-Cookie", "Set-Cookie"},
		{"其余默认前缀", DefaultHeaderPolicy(), "x-trace-id", "Grpc-Metadata-x-trace-id"},
		{"零值等效默认", HeaderPolicy{}, "set-cookie", "Set-Cookie"},
		{"Direct 追加直透", HeaderPolicy{Direct: []string{"x-replayed"}}, "x-replayed", "X-Replayed"},
		{"Direct 大小写不敏感", HeaderPolicy{Direct: []string{"x-replayed"}}, "X-REPLAYED", "X-Replayed"},
		{"显式 Direct 覆盖默认 set-cookie", HeaderPolicy{Direct: []string{"x-replayed"}}, "set-cookie", "Grpc-Metadata-set-cookie"},
	}
	for _, tc := range cases {
		m := OutgoingPolicy(tc.policy)
		got, ok := m(tc.key)
		if !ok || got != tc.wantKey {
			t.Errorf("%s: OutgoingPolicy(%+v)(%q) = (%q, %v), want (%q, true)",
				tc.name, tc.policy, tc.key, got, ok, tc.wantKey)
		}
	}
}

func TestHeaderPolicyEmptyAllowWithEmptyFallback(t *testing.T) {
	// 显式空 Allow + 空 fallback 表示不放行任何头。
	emptyAllow := HeaderPolicy{Allow: []string{}, FallbackIn: func(string) (string, bool) { return "", false }}
	if _, ok := IncomingPolicy(emptyAllow)("cookie"); ok {
		t.Fatal("empty Allow with empty fallback should not allow cookie")
	}
}
