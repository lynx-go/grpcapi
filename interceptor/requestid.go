package interceptor

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/lynx-go/grpcapi/contextx"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// RequestIDOptions 是 request ID 拦截器的配置。
type RequestIDOptions struct {
	// Header 默认 "x-request-id"（metadata key 会被小写化）。
	Header    string
	Generator func() string
	Logger    *slog.Logger
}

// RequestIDInterceptor 读取/生成 request ID，注入 ctx 并回写响应头。
type RequestIDInterceptor struct {
	header string
	gen    func() string
	logger *slog.Logger
}

// NewRequestID 构造 request ID 拦截器。
func NewRequestID(opts RequestIDOptions) *RequestIDInterceptor {
	header := strings.ToLower(strings.TrimSpace(opts.Header))
	if header == "" {
		header = "x-request-id"
	}
	gen := opts.Generator
	if gen == nil {
		gen = GenerateRequestID
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &RequestIDInterceptor{header: header, gen: gen, logger: logger}
}

// GenerateRequestID 生成 128 位随机十六进制请求 ID；熵源故障时退化为纳秒时间戳。
func GenerateRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(b[:])
}

// Unary 返回 unary request ID 拦截器。
func (r *RequestIDInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		id := r.fromContext(ctx)
		if id == "" {
			id = r.gen()
		}
		ctx = contextx.WithRequestID(ctx, id)
		if err := grpc.SetHeader(ctx, metadata.Pairs(r.header, id)); err != nil {
			r.logger.WarnContext(ctx, "requestid: set header failed", "method", info.FullMethod, "error", err)
		}
		return handler(ctx, req)
	}
}

// Stream 返回 stream request ID 拦截器。
func (r *RequestIDInterceptor) Stream() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := ss.Context()
		id := r.fromContext(ctx)
		if id == "" {
			id = r.gen()
		}
		ctx = contextx.WithRequestID(ctx, id)
		if err := ss.SetHeader(metadata.Pairs(r.header, id)); err != nil {
			r.logger.WarnContext(ctx, "requestid: set header failed", "method", info.FullMethod, "error", err)
		}
		return handler(srv, &wrappedStream{ServerStream: ss, ctx: ctx})
	}
}

func (r *RequestIDInterceptor) fromContext(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	if vs := md.Get(r.header); len(vs) > 0 {
		return strings.TrimSpace(vs[0])
	}
	return ""
}
