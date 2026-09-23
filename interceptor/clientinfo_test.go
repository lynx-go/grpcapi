package interceptor_test

import (
	"context"
	"net"
	"testing"

	"github.com/lynx-go/grpcapi/contextx"
	"github.com/lynx-go/grpcapi/interceptor"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
)

// peerCtx 构造带直连 peer 地址的 ctx（host:port 形态与真实 TCP peer 一致）。
func peerCtx(ctx context.Context, host string, port int) context.Context {
	return peer.NewContext(ctx, &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP(host), Port: port},
	})
}

// invokeClientInfo 直接以构造的 ctx 调用拦截器，捕获 handler 所见的
// ClientInfo（metadata 模拟，不经过网络）。
func invokeClientInfo(t *testing.T, ic grpc.UnaryServerInterceptor, ctx context.Context) contextx.ClientInfo {
	t.Helper()
	var got contextx.ClientInfo
	handler := func(ctx context.Context, _ any) (any, error) {
		got, _ = contextx.ClientInfoFrom(ctx)
		return nil, nil
	}
	if _, err := ic(ctx, &emptypb.Empty{}, &grpc.UnaryServerInfo{FullMethod: "/t.v1.Svc/Get"}, handler); err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}
	return got
}

func TestClientInfoDirectConnectionIgnoresForwardedHeaders(t *testing.T) {
	ic := interceptor.NewClientInfo(interceptor.ClientInfoConfig{}).Unary()
	ctx := metadata.NewIncomingContext(peerCtx(context.Background(), "203.0.113.9", 51000), metadata.Pairs(
		"x-forwarded-for", "6.6.6.6",
		"x-real-ip", "7.7.7.7",
	))
	got := invokeClientInfo(t, ic, ctx)
	if got.IP != "203.0.113.9" {
		t.Fatalf("IP = %q, want peer address %q (untrusted headers must be ignored)", got.IP, "203.0.113.9")
	}
}

func TestClientInfoTrustedProxyBacktracksXFF(t *testing.T) {
	ic := interceptor.NewClientInfo(interceptor.ClientInfoConfig{
		TrustedProxies: []string{"10.0.0.0/8"},
	}).Unary()

	t.Run("truncates client-forged hops", func(t *testing.T) {
		// 客户端伪造 XFF "1.2.3.4"；边缘代理追加真实来源 203.0.113.7，
		// 内层代理 10.0.0.2 追加后到达 10.0.0.1。自右向左回溯应在第一个
		// 不可信地址（真实客户端）停下，伪造跳被截断。
		ctx := metadata.NewIncomingContext(peerCtx(context.Background(), "10.0.0.1", 1000), metadata.Pairs(
			"x-forwarded-for", "1.2.3.4, 203.0.113.7, 10.0.0.2",
		))
		if got := invokeClientInfo(t, ic, ctx); got.IP != "203.0.113.7" {
			t.Fatalf("IP = %q, want %q", got.IP, "203.0.113.7")
		}
	})

	t.Run("untrusted peer falls back to peer address", func(t *testing.T) {
		ctx := metadata.NewIncomingContext(peerCtx(context.Background(), "192.0.2.5", 1000), metadata.Pairs(
			"x-forwarded-for", "6.6.6.6",
		))
		if got := invokeClientInfo(t, ic, ctx); got.IP != "192.0.2.5" {
			t.Fatalf("IP = %q, want %q", got.IP, "192.0.2.5")
		}
	})

	t.Run("all hops trusted yields leftmost", func(t *testing.T) {
		ctx := metadata.NewIncomingContext(peerCtx(context.Background(), "10.0.0.1", 1000), metadata.Pairs(
			"x-forwarded-for", "10.0.0.3, 10.0.0.2",
		))
		if got := invokeClientInfo(t, ic, ctx); got.IP != "10.0.0.3" {
			t.Fatalf("IP = %q, want %q", got.IP, "10.0.0.3")
		}
	})

	t.Run("x-real-ip fallback without xff", func(t *testing.T) {
		ctx := metadata.NewIncomingContext(peerCtx(context.Background(), "10.0.0.1", 1000), metadata.Pairs(
			"x-real-ip", "198.51.100.2",
		))
		if got := invokeClientInfo(t, ic, ctx); got.IP != "198.51.100.2" {
			t.Fatalf("IP = %q, want %q", got.IP, "198.51.100.2")
		}
	})

	t.Run("no forwarded headers yields peer", func(t *testing.T) {
		ctx := metadata.NewIncomingContext(peerCtx(context.Background(), "10.0.0.1", 1000), nil)
		if got := invokeClientInfo(t, ic, ctx); got.IP != "10.0.0.1" {
			t.Fatalf("IP = %q, want %q", got.IP, "10.0.0.1")
		}
	})
}

func TestClientInfoGatewayPrefixFallback(t *testing.T) {
	ic := interceptor.NewClientInfo(interceptor.ClientInfoConfig{
		TrustedProxies: []string{"10.0.0.1/32"},
	}).Unary()

	// XFF 仅以 grpcgateway- 前缀出现（gRPC 经 gateway 转发）。
	ctx := metadata.NewIncomingContext(peerCtx(context.Background(), "10.0.0.1", 2000), metadata.Pairs(
		"grpcgateway-x-forwarded-for", "198.51.100.9, 10.0.0.1",
	))
	if got := invokeClientInfo(t, ic, ctx); got.IP != "198.51.100.9" {
		t.Fatalf("IP = %q, want %q via grpcgateway- fallback", got.IP, "198.51.100.9")
	}
}

func TestClientInfoUserAgent(t *testing.T) {
	ic := interceptor.NewClientInfo(interceptor.ClientInfoConfig{}).Unary()

	t.Run("grpcgateway-user-agent preferred", func(t *testing.T) {
		ctx := metadata.NewIncomingContext(peerCtx(context.Background(), "203.0.113.9", 3000), metadata.Pairs(
			"grpcgateway-user-agent", "grpc-gateway/2.0",
			"user-agent", "grpc-go/1.83",
		))
		if got := invokeClientInfo(t, ic, ctx); got.UserAgent != "grpc-gateway/2.0" {
			t.Fatalf("UserAgent = %q", got.UserAgent)
		}
	})

	t.Run("user-agent fallback", func(t *testing.T) {
		ctx := metadata.NewIncomingContext(peerCtx(context.Background(), "203.0.113.9", 3000), metadata.Pairs(
			"user-agent", "grpc-go/1.83",
		))
		if got := invokeClientInfo(t, ic, ctx); got.UserAgent != "grpc-go/1.83" {
			t.Fatalf("UserAgent = %q", got.UserAgent)
		}
	})
}

func TestClientInfoWithoutPeerFallsBackToHeaders(t *testing.T) {
	// 无 peer 信息（进程内调用/测试）时退化为直接取 XFF 首跳。
	ic := interceptor.NewClientInfo(interceptor.ClientInfoConfig{}).Unary()
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"x-forwarded-for", "6.6.6.6, 203.0.113.9",
	))
	if got := invokeClientInfo(t, ic, ctx); got.IP != "6.6.6.6" {
		t.Fatalf("IP = %q, want %q", got.IP, "6.6.6.6")
	}
}

func TestClientInfoInvalidTrustedProxyFailsClosed(t *testing.T) {
	// 配置含无法解析的 CIDR：整个信任集作废，转发头一律不采纳。
	ic := interceptor.NewClientInfo(interceptor.ClientInfoConfig{
		TrustedProxies: []string{"10.0.0.0/8", "not-a-cidr"},
	}).Unary()
	ctx := metadata.NewIncomingContext(peerCtx(context.Background(), "10.0.0.1", 4000), metadata.Pairs(
		"x-forwarded-for", "6.6.6.6",
	))
	if got := invokeClientInfo(t, ic, ctx); got.IP != "10.0.0.1" {
		t.Fatalf("IP = %q, want peer address (fail-closed on invalid config)", got.IP)
	}
}

func TestParseTrustedProxies(t *testing.T) {
	t.Run("bare ip treated as /32", func(t *testing.T) {
		tp, err := interceptor.ParseTrustedProxies([]string{"10.0.0.1"})
		if err != nil {
			t.Fatalf("ParseTrustedProxies: %v", err)
		}
		if !tp.Trusted("10.0.0.1") {
			t.Fatal("10.0.0.1 should be trusted")
		}
		if tp.Trusted("10.0.0.2") {
			t.Fatal("10.0.0.2 should not be trusted")
		}
	})

	t.Run("rejects garbage", func(t *testing.T) {
		if _, err := interceptor.ParseTrustedProxies([]string{"999.1.2.3"}); err == nil {
			t.Fatal("expected error for invalid CIDR")
		}
	})

	t.Run("empty trusts nothing", func(t *testing.T) {
		tp, err := interceptor.ParseTrustedProxies(nil)
		if err != nil {
			t.Fatalf("ParseTrustedProxies: %v", err)
		}
		if tp.Trusted("10.0.0.1") {
			t.Fatal("nil config should trust nothing")
		}
	})
}

// echoServer 是 bufconn 端到端测试的桩服务接口（HandlerType 检查用）。
type echoServer interface {
	Get(context.Context, *emptypb.Empty) (*emptypb.Empty, error)
}

type echoImpl struct {
	capture func(ctx context.Context)
}

func (e *echoImpl) Get(ctx context.Context, req *emptypb.Empty) (*emptypb.Empty, error) {
	e.capture(ctx)
	return req, nil
}

// TestClientInfoBufconnEndToEnd 经真实 gRPC server + bufconn 连接验证
// 拦截器在链上生效（peer 提取、metadata 透传、ctx 注入）。
func TestClientInfoBufconnEndToEnd(t *testing.T) {
	ic := interceptor.NewClientInfo(interceptor.ClientInfoConfig{}).Unary()

	var got contextx.ClientInfo
	impl := &echoImpl{capture: func(ctx context.Context) {
		got, _ = contextx.ClientInfoFrom(ctx)
	}}
	desc := &grpc.ServiceDesc{
		ServiceName: "testvalidate.v1.Echo",
		HandlerType: (*echoServer)(nil),
		Methods: []grpc.MethodDesc{{
			MethodName: "Get",
			Handler: func(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
				req := &emptypb.Empty{}
				if err := dec(req); err != nil {
					return nil, err
				}
				// 与生成代码同构：先过拦截器链，再进实现。
				info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/testvalidate.v1.Echo/Get"}
				return interceptor(ctx, req, info, func(ctx context.Context, req any) (any, error) {
					return srv.(echoServer).Get(ctx, req.(*emptypb.Empty))
				})
			},
		}},
	}

	srv := grpc.NewServer(grpc.ChainUnaryInterceptor(ic))
	srv.RegisterService(desc, impl)
	lis := bufconn.Listen(1024 * 1024)
	go srv.Serve(lis)
	defer srv.Stop()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	defer conn.Close()

	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(
		"x-real-ip", "6.6.6.6", // 直连 bufnet 不可信，必须被忽略
		"grpcgateway-user-agent", "e2e-agent/1.0",
	))
	out := &emptypb.Empty{}
	if err := conn.Invoke(ctx, "/testvalidate.v1.Echo/Get", &emptypb.Empty{}, out); err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	// bufconn 的对端地址是字面 "bufconn"（非 IP 形态）：直连场景下它应
	// 原样胜出，证明不可信的 x-real-ip 被忽略。
	if got.IP != "bufconn" {
		t.Fatalf("IP = %q, want bufconn peer address (untrusted x-real-ip ignored)", got.IP)
	}
	if got.UserAgent != "e2e-agent/1.0" {
		t.Fatalf("UserAgent = %q, want e2e-agent/1.0", got.UserAgent)
	}
}
