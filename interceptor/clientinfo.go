package interceptor

import (
	"context"

	"github.com/lynx-go/grpcapi/contextx"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// ClientInfoConfig 是 clientInfo 拦截器的配置。
type ClientInfoConfig struct {
	// TrustedProxies 是可信代理网段（CIDR，接受裸 IP）。空 = 不信任
	// 任何代理转发头，一律使用 gRPC peer 地址。
	//
	// 含无法解析的条目时整个信任集按作废处理（一律不采信转发头，
	// fail-closed）；如需在启动期暴露配置错误，先经 ParseTrustedProxies
	// 校验。项目通过 config.bind 把 security.trusted_proxies 填到这里。
	TrustedProxies []string
}

// ClientInfoInterceptor 从 gRPC metadata（经 grpc-gateway 由 HTTP 头
// 透传）提取客户端 IP 与 User-Agent 注入请求 ctx。X-Forwarded-For /
// X-Real-Ip 仅在直连 peer 命中可信代理网段时被采纳（且 XFF 逐跳回溯、
// 截断客户端伪造跳），否则一律使用 gRPC peer 地址。
type ClientInfoInterceptor struct {
	trusted *TrustedProxies
}

// NewClientInfo 构造 clientInfo 拦截器。
func NewClientInfo(cfg ClientInfoConfig) *ClientInfoInterceptor {
	trusted, err := ParseTrustedProxies(cfg.TrustedProxies)
	if err != nil {
		// 构造器签名无 error：配置解析失败按 fail-closed 处理——信任集
		// 作废（一律不采信转发头）。需要启动期报错的调用方先自行调用
		// ParseTrustedProxies 校验配置。
		trusted = &TrustedProxies{invalid: true}
	}
	return &ClientInfoInterceptor{trusted: trusted}
}

// Unary 返回链首拦截器（对应 chain.SlotClientInfo）。
func (c *ClientInfoInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			ctx = contextx.WithClientInfo(ctx, c.extractClientInfo(ctx, md))
		}
		return handler(ctx, req)
	}
}

func (c *ClientInfoInterceptor) extractClientInfo(ctx context.Context, md metadata.MD) contextx.ClientInfo {
	xff := firstMetadataValue(md, "x-forwarded-for")
	if xff == "" {
		// grpc-gateway 默认会给非 IANA 永久头加 grpcgateway- 前缀。
		xff = firstMetadataValue(md, "grpcgateway-x-forwarded-for")
	}
	realIP := firstMetadataValue(md, "x-real-ip")

	var ip string
	if peerIP := PeerIP(ctx); peerIP != "" {
		ip = c.trusted.ResolveClientIP(peerIP, xff, realIP)
	} else {
		// 无 peer 信息（进程内调用/测试）时退化为直接取 XFF 首跳。
		ip = FirstForwardedHop(xff)
		if ip == "" {
			ip = realIP
		}
	}

	ua := firstMetadataValue(md, "grpcgateway-user-agent")
	if ua == "" {
		ua = firstMetadataValue(md, "user-agent")
	}
	return contextx.ClientInfo{IP: ip, UserAgent: ua}
}

func firstMetadataValue(md metadata.MD, key string) string {
	if vs := md.Get(key); len(vs) > 0 {
		return vs[0]
	}
	return ""
}
