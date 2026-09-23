// Command example 是 grpcapi 最小接入面的活文档（README 六步的每一步都在
// 此对应一段真实代码）。它不引入超出清单的必需步骤：没有 lynx、没有 Wire、
// 没有 auth 实现（SlotAuth 由项目按需插入）。
package main

import (
	"context"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/lynx-go/grpcapi/authz"
	echov1 "github.com/lynx-go/grpcapi/example/echo/v1"
	"github.com/lynx-go/grpcapi/gateway"
	"github.com/lynx-go/grpcapi/interceptor"
)

// errorBody 是 ErrorBodyBuilder 的最小实现：错误体形状是项目的产品契约，
// 库只负责机制（映射/脱敏/Retry-After），构造权在项目。
type errorBody struct{}

func (errorBody) Build(code codes.Code, message, errorID string) proto.Message {
	v, err := structpb.NewStruct(map[string]any{
		"code":     code.String(),
		"message":  message,
		"error_id": errorID,
	})
	if err != nil {
		return &structpb.Struct{}
	}
	return v
}

func (errorBody) MapErrorCode(codes.Code) any { return nil }

func main() {
	ctx := context.Background()

	// 第 3 步：注册词表并收集策略（fail-closed：词表外的 scope 资源启动即红）。
	set, err := authz.Build(
		[]protoreflect.FileDescriptor{echov1.File_echo_proto},
		authz.Options{Vocabulary: authz.Vocabulary{ScopeResources: []string{"echoes"}}},
	)
	if err != nil {
		log.Fatal(err)
	}

	// 第 4 步：拦截器链。Assemble 构造期断言槽位顺序（ClientInfo 打头、
	// Validate 收尾）；SlotAuth/SlotRateLimit/SlotAudit/SlotUsage 按需插入。
	chain, err := interceptor.Assemble(
		interceptor.ChainItem{
			Slot:        interceptor.SlotClientInfo,
			Interceptor: interceptor.NewClientInfo(interceptor.ClientInfoConfig{}).Unary(),
		},
		interceptor.ChainItem{
			Slot:        interceptor.SlotValidate,
			Interceptor: interceptor.NewValidate().Unary(),
		},
	)
	if err != nil {
		log.Fatal(err)
	}

	// 第 4 步（HTTP 面）：gateway 装配件。错误体经 ErrorBodyBuilder 注入。
	mux := gateway.NewMux(gateway.MuxOptions{
		ErrorHandler: gateway.NewErrorHandler(errorBody{}, gateway.HTTPOptions{}),
	})
	conn, err := gateway.Dial(ctx, gateway.LocalEndpoint(":9060"), gateway.DialConfig{})
	if err != nil {
		log.Fatal(err)
	}
	// 项目实际接入时，把 buf 生成的 RegisterXxxHandlerFromEndpoint 包成
	// gateway.RegisterFunc 传入 gateway.Register（example 的生成管线未含
	// gateway 插件，故此处仅演示装配件构造）：
	//
	//	err = gateway.Register(ctx, mux, conn, func(ctx context.Context,
	//		mux *runtime.ServeMux, conn grpc.ClientConnInterface) error {
	//		return echov1.RegisterEchoServiceHandler(ctx, mux, conn)
	//	})
	_ = conn
	_ = mux // 装配件就绪；项目侧 Register 后挂到 HTTP server 监听

	// 第 5 步：gRPC server + 启动断言（已注册方法缺策略即拒绝启动）。
	srv := grpc.NewServer(grpc.ChainUnaryInterceptor(chain...))
	echov1.RegisterEchoServiceServer(srv, &echoServer{})
	if err := interceptor.AssertAllRegisteredHavePolicy(srv, set); err != nil {
		log.Fatal(err)
	}

	// 第 6 步：挂守卫测试——见 example_test.go（guard.AssertMethodCount 与
	// guard.SwaggerAccessMatches；后者需要项目 buf 管线含 openapiv2 插件）。

	lis, err := net.Listen("tcp", ":9060")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("example listening on %s (HTTP mux assembled, see README)", lis.Addr())
	log.Fatal(srv.Serve(lis))
}

type echoServer struct {
	echov1.UnimplementedEchoServiceServer
}

func (s *echoServer) Shout(_ context.Context, req *echov1.ShoutRequest) (*echov1.ShoutResponse, error) {
	return &echov1.ShoutResponse{Text: req.GetText(), Length: int32(len(req.GetText()))}, nil
}

func (s *echoServer) Hear(_ context.Context, req *echov1.HearRequest) (*echov1.HearResponse, error) {
	return &echov1.HearResponse{Lines: []string{req.GetFilter()}}, nil
}

func (s *echoServer) Ping(context.Context, *echov1.PingRequest) (*echov1.PingResponse, error) {
	return &echov1.PingResponse{Pong: "pong"}, nil
}
