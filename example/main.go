// Command example 是 grpcapi v3 Tier 0 的活文档：proto 定义路由与策略，
// server.New 一步完成 gRPC + gateway + 中间件 + 启动断言。
package main

import (
	"context"
	"log"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"

	echov1 "github.com/lynx-go/grpcapi/example/echo/v1"
	"github.com/lynx-go/grpcapi/policy"
	"github.com/lynx-go/grpcapi/policy/protopolicy"
	"github.com/lynx-go/grpcapi/server"
)

func main() {
	ctx := context.Background()

	// 第 1 步：从 proto Service 收集策略（缺策略/非法值启动即红）。
	set, err := policy.Build(ctx, policy.FromFiles(echov1.File_echo_proto), policy.Options{
		Provider: protopolicy.New(protopolicy.Options{}),
		Registry: policy.DefaultRegistry(),
	})
	if err != nil {
		log.Fatal(err)
	}

	// 第 2 步：注册 Service（手写 6 行；codegen 可生成同样的 bundle）。
	desc := echov1.File_echo_proto.Services().ByName("EchoService")
	if desc == nil {
		log.Fatal("EchoService descriptor missing")
	}
	registration := server.Registration{
		API:        "public",
		Name:       "EchoService",
		Descriptor: desc,
		RegisterGRPC: func(s *grpc.Server) {
			echov1.RegisterEchoServiceServer(s, echoServer{})
		},
		RegisterHTTP: func(ctx context.Context, mux *runtime.ServeMux, conn grpc.ClientConnInterface) error {
			return echov1.RegisterEchoServiceHandlerClient(ctx, mux, echov1.NewEchoServiceClient(conn))
		},
	}

	// 第 3 步：一步装配 gRPC + gateway + 默认链 + 健康检查 + 路由表。
	// 本示例没有 authn，protected 路由会按预期返回 401；生产接入 JWT/
	// session/API key 后即可放行。
	srv, err := server.New(ctx, server.Config{
		Policy:               set,
		Services:             []server.Registration{registration},
		GRPCAddr:             ":9060",
		HTTPAddr:             ":8080",
		AllowNoAuthenticator: true,
	})
	if err != nil {
		log.Fatal(err)
	}
	for _, r := range srv.Routes() {
		log.Printf("route: %s %s -> %s (%s)", r.Method, r.Path, r.FullMethod, r.Label)
	}
	log.Fatal(srv.Run(ctx))
}

type echoServer struct {
	echov1.UnimplementedEchoServiceServer
}

func (echoServer) Shout(_ context.Context, req *echov1.ShoutRequest) (*echov1.ShoutResponse, error) {
	return &echov1.ShoutResponse{Text: req.GetText(), Length: int32(len(req.GetText()))}, nil
}

func (echoServer) Hear(_ context.Context, req *echov1.HearRequest) (*echov1.HearResponse, error) {
	return &echov1.HearResponse{Lines: []string{req.GetFilter()}}, nil
}

func (echoServer) Ping(context.Context, *echov1.PingRequest) (*echov1.PingResponse, error) {
	return &echov1.PingResponse{Pong: "pong"}, nil
}
