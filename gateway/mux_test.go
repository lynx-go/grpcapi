package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewMuxDefaultsErrorHandler(t *testing.T) {
	mux := NewMux(MuxOptions{})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/definitely-not-registered", nil))
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want default JSON error handler", ct)
	}
	if !strings.Contains(rec.Body.String(), "error_id") {
		t.Fatalf("default error body missing error_id: %s", rec.Body.String())
	}
}

func TestNewMuxWiresErrorEncoderAndHeaders(t *testing.T) {
	mux := NewMux(MuxOptions{
		ErrorEncoder: ErrorEncoderFunc(func(_ context.Context, err error) ErrorResponse {
			return ErrorResponse{
				Status: http.StatusTeapot,
				Body:   map[string]any{"wired": true},
			}
		}),
		Headers: HeaderPolicy{
			Deny:   []string{"authorization"},
			Allow:  []string{"cookie", "x-project"},
			Direct: []string{"set-cookie", "x-replayed"},
		},
	})

	// 未注册路由的请求走 mux 错误路径：必须命中自定义编码器（418 + wired），
	// 而不是 grpc-gateway 默认错误体。
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/definitely-not-registered", nil))
	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want 418（自定义 ErrorEncoder 未生效）", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"wired":true`) {
		t.Fatalf("响应体缺少自定义编码器标记: %s", rec.Body.String())
	}
}

func TestNewMuxZeroHeadersEqualDefaultPolicy(t *testing.T) {
	// Headers 零值必须与 DefaultHeaderPolicy 行为一致：authorization 拒绝、
	// cookie 放行、set-cookie 直透。
	in, out := IncomingPolicy(MuxOptions{}.Headers), OutgoingPolicy(DefaultHeaderPolicy())
	if _, ok := in("Authorization"); ok {
		t.Fatal("零值 Headers 下 authorization 必须拒绝")
	}
	if got, ok := in("Cookie"); !ok || got != "cookie" {
		t.Fatalf("零值 Headers 下 cookie 应放行: %q, %v", got, ok)
	}
	if got, ok := out("set-cookie"); !ok || got != "Set-Cookie" {
		t.Fatalf("默认出站 set-cookie 应直透: %q, %v", got, ok)
	}
}
