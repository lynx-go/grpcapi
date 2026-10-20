package interceptor

import (
	"context"
	"log/slog"
	"runtime/debug"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RecoveryOptions 是 panic 恢复拦截器的配置。
type RecoveryOptions struct {
	Logger  *slog.Logger
	OnPanic func(ctx context.Context, recovered any)
}

// RecoveryInterceptor 捕获 handler/interceptor panic，记录堆栈并返回 Internal。
type RecoveryInterceptor struct {
	opts RecoveryOptions
}

// NewRecovery 构造恢复拦截器。
func NewRecovery(opts RecoveryOptions) *RecoveryInterceptor {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &RecoveryInterceptor{opts: opts}
}

// Unary 返回 unary 恢复拦截器。
func (r *RecoveryInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		defer func() {
			if v := recover(); v != nil {
				r.handle(ctx, info.FullMethod, v)
				resp, err = nil, status.Error(codes.Internal, "internal server error")
			}
		}()
		return handler(ctx, req)
	}
}

// Stream 返回 stream 恢复拦截器。
func (r *RecoveryInterceptor) Stream() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
		defer func() {
			if v := recover(); v != nil {
				r.handle(ss.Context(), info.FullMethod, v)
				err = status.Error(codes.Internal, "internal server error")
			}
		}()
		return handler(srv, ss)
	}
}

func (r *RecoveryInterceptor) handle(ctx context.Context, method string, recovered any) {
	r.opts.Logger.ErrorContext(ctx, "panic recovered", "method", method, "panic", recovered, "stack", string(debug.Stack()))
	if r.opts.OnPanic != nil {
		r.opts.OnPanic(ctx, recovered)
	}
}
