package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewMuxRequiresErrorHandler(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("nil ErrorHandler 应在构造期 panic（fail-closed），而非等到首个错误请求")
		}
	}()
	NewMux(MuxOptions{})
}

func TestNewMuxWiresErrorHandlerAndMarshaler(t *testing.T) {
	b := &fakeBuilder{}
	mux := NewMux(MuxOptions{
		ErrorHandler:   NewErrorHandler(b, HTTPOptions{}),
		IncomingExtra:  []string{"x-torchwood-project"},
		OutgoingDirect: []string{"x-torchwood-replayed"},
	})

	// 未注册路由的请求走 mux 错误路径：必须命中我们的错误处理器
	// （application/json + error_id），而不是 grpc-gateway 默认错误体。
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/definitely-not-registered", nil))

	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type = %q, 期望统一错误处理器生效", ct)
	}
	if !strings.Contains(rec.Body.String(), "error_id") {
		t.Fatalf("响应体缺少 error_id，错误处理器未生效: %s", rec.Body.String())
	}
}
