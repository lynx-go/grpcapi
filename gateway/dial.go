package gateway

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// maxRecvMsgSize 是网关转发面的默认收包上限（8MiB，对齐 torchwood）。
const maxRecvMsgSize = 8 << 20

// DialConfig 是 Dial 的拨号选项。
type DialConfig struct {
	// TLS 为 nil 时以 insecure 凭证拨号（同机同地址部署的缺省形态）；
	// 非 nil 时以 TLS 凭证拨号。
	TLS *tls.Config

	// DialOptions 追加在库默认项之后，同字段以后者为准（grpc 选项按序合并）。
	DialOptions []grpc.DialOption
}

// LocalEndpoint 从 server grpc addr 推导 gateway 转发目标
// （平移自 torchwood grpcEndpointFromAddr）：保留原主机（缺省回环 127.0.0.1），
// 仅补充缺失的端口；无法解析 host:port 且非 ":port" 形态的地址原样返回
// （如自定义 scheme / unix: 目标）。
func LocalEndpoint(grpcAddr string) string {
	host, port, err := net.SplitHostPort(grpcAddr)
	if err != nil || port == "" {
		if grpcAddr != "" && !strings.HasPrefix(grpcAddr, ":") {
			return grpcAddr
		}
		return "127.0.0.1:9060"
	}
	if host == "" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

// Dial 建立 gateway → gRPC server 的客户端连接（grpc.NewClient，惰性连接、
// 不阻塞拨号；grpc.Dial/DialContext 已弃用，本工厂预留跟随 grpc-go API 演进）。
// 默认带 MaxCallRecvMsgSize(8MiB)；cfg.DialOptions 追加在后，同字段以后者为准。
// ctx 目前不参与连接（NewClient 无阻塞拨号语义），保留参数位。
func Dial(ctx context.Context, addr string, cfg DialConfig) (*grpc.ClientConn, error) {
	_ = ctx // 保留：grpc.NewClient 不接受 ctx；API 升级时启用
	cred := grpc.WithTransportCredentials(insecure.NewCredentials())
	if cfg.TLS != nil {
		cred = grpc.WithTransportCredentials(credentials.NewTLS(cfg.TLS))
	}
	opts := []grpc.DialOption{
		cred,
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxRecvMsgSize)),
	}
	opts = append(opts, cfg.DialOptions...)
	return grpc.NewClient(LocalEndpoint(addr), opts...)
}

// RegisterFunc 是单个服务的 gateway 注册函数。genproto 生成的
// Register*HandlerClient(ctx, mux, client) 即此形态，经闭包适配：
//
//	gateway.Register(ctx, mux, conn, func(ctx context.Context, mux *runtime.ServeMux, conn grpc.ClientConnInterface) error {
//	    return serverv1.RegisterProjectsServiceHandlerClient(ctx, mux, serverv1.NewProjectsServiceClient(conn))
//	})
type RegisterFunc func(ctx context.Context, mux *runtime.ServeMux, conn grpc.ClientConnInterface) error

// Register 依序执行注册函数，首个错误即返回。与 torchwood 的 register 循环同构。
func Register(ctx context.Context, mux *runtime.ServeMux, conn grpc.ClientConnInterface, fns ...RegisterFunc) error {
	for _, fn := range fns {
		if err := fn(ctx, mux, conn); err != nil {
			return fmt.Errorf("gateway.Register: %w", err)
		}
	}
	return nil
}
