// Package testkit 提供 server.New 的测试夹具：自动启动/关闭、HTTP/gRPC 客户端、
// 测试 Principal 与认证器。仅建议在测试代码中 import。
package testkit

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lynx-go/grpcapi/authn"
	"github.com/lynx-go/grpcapi/policy"
	"github.com/lynx-go/grpcapi/principal"
	"github.com/lynx-go/grpcapi/server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Server 是测试用 server 实例。
type Server struct {
	*server.Server
	cfg        server.Config
	cancel     context.CancelFunc
	done       chan error
	grpcConn   *grpc.ClientConn
	httpClient *http.Client
	url        string
	grpcAddr   string
}

// NewServer 启动 cfg 对应的 server，并注册 t.Cleanup。
func NewServer(t testing.TB, cfg server.Config) *Server {
	t.Helper()
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if cfg.GRPCAddr == "" && !cfg.DisableGRPC {
		cfg.GRPCAddr = "127.0.0.1:0"
	}
	if cfg.HTTPAddr == "" && !cfg.DisableHTTP {
		cfg.HTTPAddr = "127.0.0.1:0"
	}
	ctx, cancel := context.WithCancel(context.Background())
	srv, err := server.New(ctx, cfg)
	if err != nil {
		cancel()
		t.Fatalf("testkit: server.New: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()

	out := &Server{Server: srv, cfg: cfg, cancel: cancel, done: done, httpClient: &http.Client{Timeout: 10 * time.Second}}
	out.waitReady(t)
	if !cfg.DisableGRPC {
		out.grpcConn, err = grpc.NewClient(out.grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			cancel()
			t.Fatalf("testkit: grpc client: %v", err)
		}
	}
	if !cfg.DisableHTTP {
		out.url = "http://" + out.httpAddr()
	}
	t.Cleanup(func() {
		cancel()
		if out.grpcConn != nil {
			_ = out.grpcConn.Close()
		}
		select {
		case err := <-done:
			// Run 取消路径返回 Shutdown 的结果（nil = 优雅退出）；
			// 非nil 说明装配体在清理时出了问题，测试必须看到。
			if err != nil {
				t.Errorf("testkit: server.Run after cancel: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Errorf("testkit: server did not shut down")
		}
	})
	return out
}

func (s *Server) waitReady(t testing.TB) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		grpcAddr, httpAddr := s.Addrs()
		if s.cfg.DisableGRPC {
			grpcAddr = ""
		}
		if s.cfg.DisableHTTP {
			httpAddr = ""
		}
		if (s.cfg.DisableGRPC || grpcAddr != "") && (s.cfg.DisableHTTP || httpAddr != "") {
			s.grpcAddr = grpcAddr
			return
		}
		select {
		case err := <-s.done:
			t.Fatalf("testkit: server exited early: %v", err)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("testkit: server did not start within 10s")
}

func (s *Server) httpAddr() string {
	_, addr := s.Addrs()
	return addr
}

// GRPC 返回测试 gRPC 连接；DisableGRPC 时为 nil。
func (s *Server) GRPC() *grpc.ClientConn { return s.grpcConn }

// HTTP 返回测试 HTTP 客户端。
func (s *Server) HTTP() *http.Client { return s.httpClient }

// URL 返回 HTTP base URL；DisableHTTP 时为空。
func (s *Server) URL() string { return s.url }

// Principal 构造测试 Principal。
func Principal(kind string, claims map[string][]string) *principal.Principal {
	if kind == "" {
		kind = principal.KindUser
	}
	return &principal.Principal{ID: "test-" + kind, Kind: kind, Claims: claims}
}

// WithPrincipal 将 Principal 注入 ctx（用于直调 unary/stream 拦截器）。
func WithPrincipal(ctx context.Context, p *principal.Principal) context.Context {
	return principal.With(ctx, p)
}

// BuildPolicy 构建策略集；失败直接 Fatal。
func BuildPolicy(t testing.TB, src policy.Source, opts policy.Options) *policy.Set {
	t.Helper()
	set, err := policy.Build(context.Background(), src, opts)
	if err != nil {
		t.Fatalf("testkit: policy.Build: %v", err)
	}
	return set
}

// StaticAuthenticator 对任何被识别的凭证返回固定 Principal。
// 网络测试需要携带任意凭证（如 Authorization: Bearer test）才会触发认证。
func StaticAuthenticator(p *principal.Principal) authn.Authenticator {
	return staticAuthenticator{p: p}
}

type staticAuthenticator struct{ p *principal.Principal }

func (a staticAuthenticator) Name() string { return "static" }
func (a staticAuthenticator) Authenticate(context.Context, authn.Credentials) (*principal.Principal, error) {
	return a.p.Clone(), nil
}

// HeaderAuthenticator 从 header/metadata 读取主体 ID，返回 user Principal。
// HTTP 用 header，gRPC 用同名 metadata。
func HeaderAuthenticator(header string) authn.Authenticator {
	return headerAuthenticator{header: strings.ToLower(strings.TrimSpace(header))}
}

type headerAuthenticator struct{ header string }

func (a headerAuthenticator) Name() string { return "header" }
func (a headerAuthenticator) Authenticate(_ context.Context, c authn.Credentials) (*principal.Principal, error) {
	var id string
	if c.HTTP != nil {
		id = c.HTTP.Header.Get(a.header)
	} else if vs := c.Metadata.Get(a.header); len(vs) > 0 {
		id = vs[0]
	}
	if id == "" {
		return nil, nil
	}
	return &principal.Principal{
		ID:     id,
		Kind:   principal.KindUser,
		Claims: map[string][]string{"roles": {"test"}},
	}, nil
}

var _ fmt.Stringer = (*Server)(nil)

func (s *Server) String() string {
	return fmt.Sprintf("testkit.Server{url:%s}", s.url)
}
