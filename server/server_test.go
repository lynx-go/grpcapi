package server_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/lynx-go/grpcapi/example/echo/v1"
	"github.com/lynx-go/grpcapi/interceptor"
	"github.com/lynx-go/grpcapi/policy"
	"github.com/lynx-go/grpcapi/policy/protopolicy"
	"github.com/lynx-go/grpcapi/server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

type echoImpl struct {
	echov1.UnimplementedEchoServiceServer
}

func (echoImpl) Shout(_ context.Context, req *echov1.ShoutRequest) (*echov1.ShoutResponse, error) {
	return &echov1.ShoutResponse{Text: req.GetText(), Length: int32(len(req.GetText()))}, nil
}
func (echoImpl) Hear(_ context.Context, req *echov1.HearRequest) (*echov1.HearResponse, error) {
	return &echov1.HearResponse{Lines: []string{req.GetFilter()}}, nil
}
func (echoImpl) Ping(context.Context, *echov1.PingRequest) (*echov1.PingResponse, error) {
	return &echov1.PingResponse{Pong: "pong"}, nil
}

func testSet(t *testing.T) *policy.Set {
	t.Helper()
	set, err := policy.Build(context.Background(), policy.FromFiles(echov1.File_echo_proto), policy.Options{
		Provider: protopolicy.New(protopolicy.Options{}),
		Registry: policy.DefaultRegistry(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func testRegistration(t *testing.T) server.Registration {
	t.Helper()
	desc := echov1.File_echo_proto.Services().ByName("EchoService")
	if desc == nil {
		t.Fatal("EchoService descriptor missing")
	}
	impl := echoImpl{}
	return server.Registration{
		API:        "public",
		Name:       "EchoService",
		Descriptor: desc,
		RegisterGRPC: func(s *grpc.Server) {
			echov1.RegisterEchoServiceServer(s, impl)
		},
		RegisterHTTP: func(ctx context.Context, mux *runtime.ServeMux, conn grpc.ClientConnInterface) error {
			return echov1.RegisterEchoServiceHandlerClient(ctx, mux, echov1.NewEchoServiceClient(conn))
		},
	}
}

func newTestServer(t *testing.T) *server.Server {
	t.Helper()
	s, err := server.New(context.Background(), server.Config{
		Policy:               testSet(t),
		Services:             []server.Registration{testRegistration(t)},
		GRPCAddr:             "127.0.0.1:0",
		HTTPAddr:             "127.0.0.1:0",
		DisableHealth:        true,
		AllowNoAuthenticator: true,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return s
}

func TestServerEndToEnd(t *testing.T) {
	s := newTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx) }()

	var httpAddr string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, httpAddr = s.Addrs()
		if httpAddr != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if httpAddr == "" {
		cancel()
		t.Fatal("server did not start")
	}

	resp, err := http.Get("http://" + httpAddr + "/v1/echo:ping")
	if err != nil {
		cancel()
		t.Fatalf("GET ping: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "pong") {
		cancel()
		t.Fatalf("ping status=%d body=%s", resp.StatusCode, body)
	}

	resp, err = http.Get("http://" + httpAddr + "/v1/echo")
	if err != nil {
		cancel()
		t.Fatalf("GET hear: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		cancel()
		t.Fatalf("protected route status=%d, want 401", resp.StatusCode)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down")
	}
}

func TestServerHealthCheckBypassesAuthz(t *testing.T) {
	s, err := server.New(context.Background(), server.Config{
		Policy:               testSet(t),
		Services:             []server.Registration{testRegistration(t)},
		GRPCAddr:             "127.0.0.1:0",
		DisableHTTP:          true,
		AllowNoAuthenticator: true,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx) }()

	var grpcAddr string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		grpcAddr, _ = s.Addrs()
		if grpcAddr != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if grpcAddr == "" {
		cancel()
		t.Fatal("server did not start")
	}
	conn, err := grpc.NewClient(grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		cancel()
		t.Fatalf("grpc.NewClient: %v", err)
	}
	defer conn.Close()
	callCtx, callCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer callCancel()
	resp, err := healthpb.NewHealthClient(conn).Check(callCtx, &healthpb.HealthCheckRequest{})
	if err != nil {
		cancel()
		t.Fatalf("health check: %v", err)
	}
	if resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		cancel()
		t.Fatalf("health status = %v", resp.GetStatus())
	}
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down")
	}
}

func TestServerRejectsExtraRouteShadowingPrefixedProtoRoute(t *testing.T) {
	_, err := server.New(context.Background(), server.Config{
		Policy: testSet(t),
		APIs: []server.APIConfig{{
			Name:     "public",
			Prefix:   "/api",
			Services: []server.Registration{testRegistration(t)},
		}},
		ExtraRoutes: []server.ExtraRoute{
			server.GET("/api/v1/echo", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).Public(),
		},
		DisableGRPC:          true,
		DisableHealth:        true,
		AllowNoAuthenticator: true,
	})
	if err == nil || !strings.Contains(err.Error(), "conflicts with proto route") {
		t.Fatalf("error = %v, want prefixed route conflict", err)
	}
}

func TestExtraRouteSupportsCustomRequirementKind(t *testing.T) {
	reg := policy.DefaultRegistry()
	if err := reg.Register(policy.RequirementKind{
		Name:         "tenant",
		DefaultMatch: policy.MatchAny,
		Evaluate: func(_ context.Context, ec policy.EvalContext, req policy.Requirement) (bool, error) {
			if ec.Principal == nil {
				return false, nil
			}
			got := ec.Principal.Claim("tenant")
			for _, want := range req.Values {
				for _, v := range got {
					if v == want {
						return true, nil
					}
				}
			}
			return false, nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	set, err := policy.NewSetWithRegistry(reg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = server.New(context.Background(), server.Config{
		Policy: set,
		ExtraRoutes: []server.ExtraRoute{
			server.GET("/tenant", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).
				Require(policy.Policy{Require: []policy.Requirement{{Kind: "tenant", Values: []string{"acme"}}}}),
		},
		DisableGRPC:          true,
		DisableHealth:        true,
		AllowNoAuthenticator: true,
	})
	if err != nil {
		t.Fatalf("custom kind ExtraRoute rejected: %v", err)
	}
}

func TestServerRejectsPolicyWithoutRegistration(t *testing.T) {
	set, err := policy.Build(context.Background(), policy.FromFiles(echov1.File_echo_proto), policy.Options{
		Provider: protopolicy.New(protopolicy.Options{}),
		Registry: policy.DefaultRegistry(),
	})
	if err != nil {
		t.Fatal(err)
	}
	set, err = set.WithOperations(policy.Operation{
		ID: "/other.Service/Get", Kind: policy.KindGRPC,
		Exposure: policy.ExposureInternal, Policy: policy.Policy{Anonymous: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = server.New(context.Background(), server.Config{
		Policy:      set,
		DisableHTTP: true,
	})
	if err == nil || !strings.Contains(err.Error(), "without registration") {
		t.Fatalf("error = %v, want unregistered policy error", err)
	}
}

func TestServerRejectsShadowedPrefixes(t *testing.T) {
	_, err := server.New(context.Background(), server.Config{
		Policy: testSet(t),
		APIs: []server.APIConfig{
			{Name: "public", Prefix: "/v1", Services: []server.Registration{testRegistration(t)}},
			{Name: "admin", Prefix: "/v1/admin"},
		},
		GRPCAddr:             "127.0.0.1:0",
		HTTPAddr:             "127.0.0.1:0",
		DisableHealth:        true,
		AllowNoAuthenticator: true,
	})
	if err == nil || !strings.Contains(err.Error(), "shadowed") {
		t.Fatalf("error = %v, want prefix shadow error", err)
	}

	// path 段边界：/v1 与 /v1admin 不构成遮蔽，应能通过装配。
	if _, err := server.New(context.Background(), server.Config{
		Policy: testSet(t),
		APIs: []server.APIConfig{
			{Name: "public", Prefix: "/v1", Services: []server.Registration{testRegistration(t)}},
			{Name: "admin", Prefix: "/v1admin"},
		},
		GRPCAddr:             "127.0.0.1:0",
		HTTPAddr:             "127.0.0.1:0",
		DisableHealth:        true,
		AllowNoAuthenticator: true,
	}); err != nil {
		t.Fatalf("boundary prefixes should not shadow: %v", err)
	}
}

func TestServerRejectsAuthzBeforeAuthn(t *testing.T) {
	trivial := func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		return handler(ctx, req)
	}
	trivialStream := func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return handler(srv, ss)
	}
	// Assemble 按 Order 升序会拒绝乱序声明；自定义 Order 仍能组装出
	// authz 先于 authn 执行的链，由 server 启动断言兜底。
	chain, err := interceptor.Assemble(
		interceptor.StageOf(interceptor.StageAuthz, 10, trivial, trivialStream),
		interceptor.StageOf(interceptor.StageAuthn, 20, trivial, trivialStream),
	)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	_, err = server.New(context.Background(), server.Config{
		Policy:               testSet(t),
		Services:             []server.Registration{testRegistration(t)},
		GRPCAddr:             "127.0.0.1:0",
		HTTPAddr:             "127.0.0.1:0",
		DisableHealth:        true,
		AllowNoAuthenticator: true,
		Chain:                chain,
	})
	if err == nil || !strings.Contains(err.Error(), "before authn") {
		t.Fatalf("error = %v, want authz-before-authn error", err)
	}
}

func TestServerEnforcesHTTPBodyLimit(t *testing.T) {
	// HTTP 请求体上限与 MaxRecvMsgSize 同源：protojson 解码不受 gRPC
	// 消息上限保护，超限 body 必须在读入阶段失败，而不是进到业务语义。
	s, err := server.New(context.Background(), server.Config{
		Policy:               testSet(t),
		Services:             []server.Registration{testRegistration(t)},
		GRPCAddr:             "127.0.0.1:0",
		HTTPAddr:             "127.0.0.1:0",
		DisableHealth:        true,
		AllowNoAuthenticator: true,
		MaxRecvMsgSize:       64,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx) }()

	var httpAddr string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, httpAddr = s.Addrs()
		if httpAddr != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if httpAddr == "" {
		t.Fatal("server did not start")
	}

	post := func(body string) int {
		resp, err := http.Post("http://"+httpAddr+"/v1/echo:shout", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	// 超限 body：在读入/解码阶段失败（不得落入 authz 的 403，说明请求
	// 根本没走到业务语义）。
	if got := post(`{"text":"` + strings.Repeat("x", 1024) + `"}`); got < 400 || got == http.StatusForbidden {
		t.Fatalf("oversized body status = %d, want >=400 decode failure before authz", got)
	}
	// 正常 body：解码成功，到达 authz 被拒（无 principal → 401）。
	if got := post(`{"text":"hi"}`); got != http.StatusUnauthorized {
		t.Fatalf("normal body status = %d, want 401 (decoded, authz denied)", got)
	}
}

func TestServerExtraRouteBodyLimitExemption(t *testing.T) {
	// 全局上限保持紧（与 MaxRecvMsgSize 同源 64B），上传路由经
	// MaxBodyBytes 逐路由放宽：豁免只作用于该 extra route，不放大
	// proto 路由或 gRPC 消息上限。
	upload := server.POST("/upload", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			http.Error(w, "read body failed", http.StatusBadRequest)
			return
		}
		fmt.Fprintf(w, "ok %d\n", n)
	})).Public()
	upload.MaxBodyBytes = 4096

	s, err := server.New(context.Background(), server.Config{
		Policy:               testSet(t),
		Services:             []server.Registration{testRegistration(t)},
		ExtraRoutes:          []server.ExtraRoute{upload},
		GRPCAddr:             "127.0.0.1:0",
		HTTPAddr:             "127.0.0.1:0",
		DisableHealth:        true,
		AllowNoAuthenticator: true,
		MaxRecvMsgSize:       64,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx) }()

	var httpAddr string
	deadline := time.Now().Add(5 * time.Second)
	for now := time.Now(); now.Before(deadline); now = time.Now() {
		_, httpAddr = s.Addrs()
		if httpAddr != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if httpAddr == "" {
		t.Fatal("server did not start")
	}

	post := func(path string, size int) int {
		resp, err := http.Post("http://"+httpAddr+path, "application/octet-stream",
			strings.NewReader(strings.Repeat("x", size)))
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}

	// 豁免路由：1KiB（远超全局 64B）成功；超 4096 上限在读入阶段失败。
	if got := post("/upload", 1024); got != http.StatusOK {
		t.Fatalf("exempted upload status = %d, want 200", got)
	}
	if got := post("/upload", 8192); got < 400 {
		t.Fatalf("oversized upload status = %d, want >=400", got)
	}
	// proto 路由仍按全局 64B 上限拒绝，未被豁免放大。
	if got := post("/v1/echo:shout", 1024); got < 400 || got == http.StatusForbidden {
		t.Fatalf("proto route status = %d, want >=400 decode failure before authz", got)
	}
}

func TestServerHTTPBodyLimitDecoupled(t *testing.T) {
	// HTTPBodyLimitBytes 显式解耦：全局 HTTP 上限 4096，gRPC 消息上限保持
	// 64——两种语义不再互相牵引。
	if _, err := server.New(context.Background(), server.Config{
		Policy:               testSet(t),
		Services:             []server.Registration{testRegistration(t)},
		GRPCAddr:             "127.0.0.1:0",
		HTTPAddr:             "127.0.0.1:0",
		DisableHealth:        true,
		AllowNoAuthenticator: true,
		MaxRecvMsgSize:       64,
		HTTPBodyLimitBytes:   4096,
	}); err != nil {
		t.Fatalf("server.New: %v", err)
	}
	if _, err := server.New(context.Background(), server.Config{
		HTTPBodyLimitBytes: -1,
	}); err == nil || !strings.Contains(err.Error(), "HTTPBodyLimitBytes") {
		t.Fatalf("error = %v, want negative HTTPBodyLimitBytes rejection", err)
	}
	if _, err := server.New(context.Background(), server.Config{
		ExtraRoutes: []server.ExtraRoute{func() server.ExtraRoute {
			r := server.POST("/x", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {})).Public()
			r.MaxBodyBytes = -1
			return r
		}()},
	}); err == nil || !strings.Contains(err.Error(), "MaxBodyBytes") {
		t.Fatalf("error = %v, want negative MaxBodyBytes rejection", err)
	}
}

// lynx 形态集成：宿主框架用自己的 http.Server 包住 HTTPHandler、自管 gRPC
// listener——server.New 只负责装配与启动断言,不与宿主 runner 争夺生命周期。
func TestServerLynxStyleIntegration(t *testing.T) {
	s, err := server.New(context.Background(), server.Config{
		Policy:               testSet(t),
		Services:             []server.Registration{testRegistration(t)},
		GRPCAddr:             "127.0.0.1:0",
		DisableHealth:        true,
		AllowNoAuthenticator: true,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	// gRPC 侧：调用方持有 listener,Serve 由宿主驱动。
	grpcLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	grpcSrv := s.GRPCServer()
	if grpcSrv == nil {
		t.Fatal("GRPCServer() = nil")
	}
	go func() { _ = grpcSrv.Serve(grpcLis) }()

	// HTTP 侧：httptest.NewServer 正是 lynxhttp.NewServer(handler) 的形态
	//(外部 http.Server 包住我们的 handler)。
	handler := s.HTTPHandler()
	if handler == nil {
		t.Fatal("HTTPHandler() = nil")
	}
	httpSrv := httptest.NewServer(handler)
	defer httpSrv.Close()

	// HTTP 面经 in-process gateway 打到 gRPC 实现。
	resp, err := http.Get(httpSrv.URL + "/v1/echo:ping")
	if err != nil {
		t.Fatalf("GET ping via external http.Server: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "pong") {
		t.Fatalf("ping status=%d body=%s", resp.StatusCode, body)
	}

	// Shutdown 与宿主持有的 Serve 循环兼容（GracefulStop 同一实例）。
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

// HTTPHandler 先于 Run 调用时,Run 不得重复启动内部 bufconn server。
func TestServerHTTPHandlerThenRunNoDoubleStart(t *testing.T) {
	s, err := server.New(context.Background(), server.Config{
		Policy:               testSet(t),
		Services:             []server.Registration{testRegistration(t)},
		GRPCAddr:             "127.0.0.1:0",
		HTTPAddr:             "127.0.0.1:0",
		DisableHealth:        true,
		AllowNoAuthenticator: true,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	_ = s.HTTPHandler() // 先启动内部 gRPC(幂等)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx) }()
	defer func() { cancel(); <-errCh }()

	var httpAddr string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, httpAddr = s.Addrs()
		if httpAddr != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if httpAddr == "" {
		t.Fatal("server did not start")
	}
	resp, err := http.Get("http://" + httpAddr + "/v1/echo:ping")
	if err != nil {
		t.Fatalf("GET ping after HTTPHandler+Run: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "pong") {
		t.Fatalf("ping status=%d body=%s", resp.StatusCode, body)
	}
}
