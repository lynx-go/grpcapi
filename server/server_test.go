package server_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/lynx-go/grpcapi/example/echo/v1"
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
