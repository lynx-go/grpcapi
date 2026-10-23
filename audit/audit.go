// Package audit 提供 slog 落审计参考实现，填 interceptor.AuditStage 槽位。
//
// 事件在 handler 完成后记录（结果码、耗时、身份、来源 IP 可用）。落审计是
// best-effort 契约：Sink 返回错误或 panic 只记日志，绝不影响请求结果——审计
// 故障拖垮业务面比丢一条审计严重。噪声治理（哪些方法够格落审计）经 Include
// 判定；落库/消息队列/异步化由项目经 Sink 自行接管，本参考实现只演示结构。
package audit

import (
	"context"
	"log/slog"
	"time"

	"github.com/lynx-go/grpcapi/contextx"
	"github.com/lynx-go/grpcapi/interceptor"
	"github.com/lynx-go/grpcapi/principal"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Event 是一次已完结请求的审计记录。
type Event struct {
	Time          time.Time
	Method        string
	PrincipalID   string
	PrincipalKind string
	Anonymous     bool
	ClientIP      string
	UserAgent     string
	Code          codes.Code
	Duration      time.Duration
}

// Options 是审计拦截器的配置。
type Options struct {
	// Logger 是默认落点（slog Info 级）；nil = slog.Default()。
	Logger *slog.Logger
	// Sink 是自定义落点（落库/消息队列）。设置后替代 Logger 输出；
	// 异步化（channel + worker）由调用方在 Sink 内自行包一层。
	Sink func(ctx context.Context, e Event)
	// Include 是落审计资格判定（噪声治理）：返回 false 跳过该方法。
	// nil = 全部落。判定发生在请求开始前，失败请求也会落审计。
	Include func(ctx context.Context, fullMethod string) bool
}

// Interceptor 是审计拦截器。
type Interceptor struct {
	opts Options
}

// New 构造审计拦截器。
func New(opts Options) *Interceptor {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Interceptor{opts: opts}
}

// Unary 返回 unary 审计拦截器。
func (i *Interceptor) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if i.opts.Include != nil && !i.opts.Include(ctx, info.FullMethod) {
			return handler(ctx, req)
		}
		start := time.Now()
		resp, err := handler(ctx, req)
		i.record(ctx, info.FullMethod, start, err)
		return resp, err
	}
}

// Stream 返回 stream 审计拦截器（流建立到结束计一次）。
func (i *Interceptor) Stream() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if i.opts.Include != nil && !i.opts.Include(ss.Context(), info.FullMethod) {
			return handler(srv, ss)
		}
		start := time.Now()
		err := handler(srv, ss)
		i.record(ss.Context(), info.FullMethod, start, err)
		return err
	}
}

func (i *Interceptor) record(ctx context.Context, method string, start time.Time, err error) {
	e := Event{
		Time:     start,
		Method:   method,
		Code:     status.Code(err),
		Duration: time.Since(start),
	}
	if p, ok := principal.From(ctx); ok {
		e.PrincipalID = p.ID
		e.PrincipalKind = p.Kind
	} else {
		e.Anonymous = true
	}
	if ci, ok := contextx.ClientInfoFrom(ctx); ok {
		e.ClientIP = ci.IP
		e.UserAgent = ci.UserAgent
	}
	defer func() {
		// best-effort：Sink panic 不拖垮请求路径（Recovery 已在链首兜底，
		// 这里补记录动作自身的兜底）。
		if v := recover(); v != nil {
			i.opts.Logger.ErrorContext(ctx, "audit: sink panicked", "method", method, "panic", v)
		}
	}()
	if i.opts.Sink != nil {
		i.opts.Sink(ctx, e)
		return
	}
	i.opts.Logger.InfoContext(ctx, "audit",
		"method", e.Method,
		"principal_id", e.PrincipalID,
		"principal_kind", e.PrincipalKind,
		"anonymous", e.Anonymous,
		"client_ip", e.ClientIP,
		"code", e.Code.String(),
		"duration_ms", e.Duration.Milliseconds(),
	)
}

// Stage 返回可直接进 interceptor.Assemble 的 audit Stage。
func (i *Interceptor) Stage() interceptor.Stage {
	return interceptor.AuditStage(i.Unary(), i.Stream())
}
