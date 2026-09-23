package gateway

import (
	"testing"
)

func TestIncomingMatcher(t *testing.T) {
	cases := []struct {
		name      string
		extra     []string
		key       string
		wantKey   string
		wantAllow bool
	}{
		// authorization 恒拒绝：matcher 放行会与 grpc-gateway 内置透传双写，
		// 服务端多凭证判定 401。
		{"authorization 拒绝", nil, "Authorization", "", false},
		{"authorization 小写拒绝", nil, "authorization", "", false},
		{"cookie 放行", nil, "Cookie", "cookie", true},
		{"cookie 小写放行", nil, "cookie", "cookie", true},
		{"x-api-key 放行", nil, "X-Api-Key", "x-api-key", true},
		{"x-request-id 放行", nil, "X-Request-Id", "x-request-id", true},
		{"idempotency-key 放行", nil, "Idempotency-Key", "idempotency-key", true},
		{"普通自定义头拒绝", nil, "X-Custom", "", false},
		{"grpc 系统头保留", nil, "Grpc-Metadata-Foo", "Foo", true},
		{"标准头默认透传", nil, "Accept-Language", "grpcgateway-Accept-Language", true},
		{"extraAllow 项目头", []string{"X-Torchwood-Project"}, "X-Torchwood-Project", "x-torchwood-project", true},
		{"extraAllow 未命中仍拒绝", []string{"X-Torchwood-Project"}, "X-Other", "", false},
	}
	for _, tc := range cases {
		m := IncomingMatcher(tc.extra...)
		got, ok := m(tc.key)
		if ok != tc.wantAllow || (ok && got != tc.wantKey) {
			t.Errorf("%s: IncomingMatcher(%v)(%q) = (%q, %v), want (%q, %v)",
				tc.name, tc.extra, tc.key, got, ok, tc.wantKey, tc.wantAllow)
		}
	}
}

func TestOutgoingMatcher(t *testing.T) {
	cases := []struct {
		name    string
		direct  []string
		key     string
		wantKey string
	}{
		{"set-cookie 直透", nil, "set-cookie", "Set-Cookie"},
		{"set-cookie 大小写不敏感", nil, "Set-Cookie", "Set-Cookie"},
		{"其余默认前缀", nil, "x-trace-id", "Grpc-Metadata-x-trace-id"},
		{"direct 追加直透", []string{"x-torchwood-replayed"}, "x-torchwood-replayed", "X-Torchwood-Replayed"},
		{"direct 大小写不敏感", []string{"X-Torchwood-Replayed"}, "X-TORCHWOOD-REPLAYED", "X-Torchwood-Replayed"},
	}
	for _, tc := range cases {
		m := OutgoingMatcher(tc.direct...)
		got, ok := m(tc.key)
		if !ok || got != tc.wantKey {
			t.Errorf("%s: OutgoingMatcher(%v)(%q) = (%q, %v), want (%q, true)",
				tc.name, tc.direct, tc.key, got, ok, tc.wantKey)
		}
	}
}
