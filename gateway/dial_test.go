package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
)

func TestLocalEndpoint(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"空地址回缺省", "", "127.0.0.1:9060"},
		{"仅端口补回环", ":9060", "127.0.0.1:9060"},
		{"0.0.0.0 保留主机", "0.0.0.0:9060", "0.0.0.0:9060"},
		{"回环原样", "127.0.0.1:9060", "127.0.0.1:9060"},
		{"IPv6 加括号", "[::1]:9060", "[::1]:9060"},
		{"裸主机名原样", "myhost", "myhost"},
		{"裸端口号原样（保留 torchwood 语义）", "9060", "9060"},
	}
	for _, tc := range cases {
		if got := LocalEndpoint(tc.in); got != tc.want {
			t.Errorf("%s: LocalEndpoint(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}

func TestDial(t *testing.T) {
	conn, err := Dial(context.Background(), ":9060", DialConfig{})
	if err != nil {
		t.Fatalf("insecure Dial: %v", err)
	}
	defer conn.Close()
	if got := conn.Target(); got != "127.0.0.1:9060" {
		t.Fatalf("目标 = %q, want 127.0.0.1:9060（LocalEndpoint 规整应生效）", got)
	}

	tlsConn, err := Dial(context.Background(), "0.0.0.0:1234", DialConfig{TLS: &tls.Config{}})
	if err != nil {
		t.Fatalf("TLS Dial: %v", err)
	}
	defer tlsConn.Close()
	if got := tlsConn.Target(); got != "0.0.0.0:1234" {
		t.Fatalf("TLS 目标 = %q, want 0.0.0.0:1234", got)
	}

	customConn, err := Dial(context.Background(), ":9060", DialConfig{
		DialOptions: []grpc.DialOption{grpc.WithUserAgent("grpcapi-test")},
	})
	if err != nil {
		t.Fatalf("自定义 DialOptions Dial: %v", err)
	}
	defer customConn.Close()
}

func TestRegister(t *testing.T) {
	mux := NewMux(MuxOptions{ErrorHandler: errorHandlerForTest(nil, HTTPOptions{})})
	ctx := context.Background()

	calls := 0
	fn := func(ctx context.Context, mux *runtime.ServeMux, conn grpc.ClientConnInterface) error {
		calls++
		return nil
	}
	if err := Register(ctx, mux, nil, fn, fn); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if calls != 2 {
		t.Fatalf("注册函数调用次数 = %d, want 2", calls)
	}

	boom := errors.New("boom")
	err := Register(ctx, mux, nil, func(context.Context, *runtime.ServeMux, grpc.ClientConnInterface) error {
		return boom
	})
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("注册错误应向上传播: %v", err)
	}
}
