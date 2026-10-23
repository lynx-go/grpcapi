// Package ratelimit 提供固定窗口内存限流参考实现，填 interceptor.RateLimitStage
// 槽位。
//
// 定位是参考实现而非基础设施：单进程内计数，重启清零，多副本部署时每副本
// 独立限额（N 副本 ≈ 总限额 ×N，需要全局精确限额请自行接 Redis/网关，再经
// 同一 Stage 槽位挂入）。默认键取 principal ID，无身份回落 client IP，再回落
// 匿名桶——认证之后（Stage 顺序 authn < ratelimit）principal 已可用。
package ratelimit

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/lynx-go/grpcapi/contextx"
	"github.com/lynx-go/grpcapi/interceptor"
	"github.com/lynx-go/grpcapi/principal"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

// Options 是限流器配置。
type Options struct {
	// Limit 是每个窗口内允许的请求数（按 Key 分组计数）；必须 > 0。
	Limit int
	// Window 是固定窗口时长；默认 1 分钟，必须 > 0。
	Window time.Duration
	// Key 生成分组键；nil = principal ID 优先，无身份回落 client IP，
	// 再回落 "anonymous"（全匿名共享一桶）。返回空串等同默认键。
	Key func(ctx context.Context, fullMethod string) string
	// OnLimited 在请求被限流时回调（计数/告警）；不得阻塞请求路径。
	OnLimited func(ctx context.Context, key string, retryAfter time.Duration)
	Logger    *slog.Logger
}

func (o Options) normalize() Options {
	if o.Window <= 0 {
		o.Window = time.Minute
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return o
}

type window struct {
	start time.Time
	count int
}

// Limiter 是固定窗口内存限流器。
type Limiter struct {
	opts Options

	mu        sync.Mutex
	windows   map[string]*window
	lastSweep time.Time
}

// New 构造限流器；非法配置（Limit<=0）返回错误（fail-closed，拒绝静默
// 构造出"永不限流"的实例）。
func New(opts Options) (*Limiter, error) {
	if opts.Limit <= 0 {
		return nil, fmt.Errorf("ratelimit: Limit must be > 0, got %d", opts.Limit)
	}
	opts = opts.normalize()
	return &Limiter{
		opts:      opts,
		windows:   map[string]*window{},
		lastSweep: time.Now(),
	}, nil
}

// Allow 报告 key 在当前窗口是否放行，并给出建议退避时长。
func (l *Limiter) Allow(ctx context.Context, key string) (bool, time.Duration) {
	if key == "" {
		key = defaultKey(ctx)
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked(now)
	w, ok := l.windows[key]
	if !ok || now.Sub(w.start) >= l.opts.Window {
		l.windows[key] = &window{start: now, count: 1}
		return true, 0
	}
	if w.count >= l.opts.Limit {
		return false, l.opts.Window - now.Sub(w.start)
	}
	w.count++
	return true, 0
}

// sweepLocked 清理过期窗口，避免长期运行的键累积。每次 Allow 都检查，
// 但最多每窗口一轮全量扫描。
func (l *Limiter) sweepLocked(now time.Time) {
	if now.Sub(l.lastSweep) < l.opts.Window {
		return
	}
	l.lastSweep = now
	for k, w := range l.windows {
		if now.Sub(w.start) >= l.opts.Window {
			delete(l.windows, k)
		}
	}
}

func defaultKey(ctx context.Context) string {
	if p, ok := principal.From(ctx); ok && p.ID != "" {
		return "principal:" + p.ID
	}
	if ci, ok := contextx.ClientInfoFrom(ctx); ok && ci.IP != "" {
		return "ip:" + ci.IP
	}
	return "anonymous"
}

// Unary 返回 unary 限流拦截器；超限返回 ResourceExhausted 并携带
// errdetails.RetryInfo（gateway 错误编码器会转成 Retry-After 头）。
func (l *Limiter) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := l.check(ctx, info.FullMethod); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// Stream 返回 stream 限流拦截器（每次流建立计一次）。
func (l *Limiter) Stream() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := l.check(ss.Context(), info.FullMethod); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

func (l *Limiter) check(ctx context.Context, fullMethod string) error {
	key := defaultKey(ctx)
	if l.opts.Key != nil {
		key = l.opts.Key(ctx, fullMethod)
	}
	ok, retryAfter := l.Allow(ctx, key)
	if ok {
		return nil
	}
	if retryAfter < time.Second {
		retryAfter = time.Second
	}
	if l.opts.OnLimited != nil {
		l.opts.OnLimited(ctx, key, retryAfter)
	}
	l.opts.Logger.WarnContext(ctx, "ratelimit: request limited",
		"method", fullMethod, "key", key, "retry_after", retryAfter.String())
	st := status.New(codes.ResourceExhausted, "rate limit exceeded")
	st, err := st.WithDetails(&errdetails.RetryInfo{RetryDelay: durationpb.New(retryAfter)})
	if err != nil {
		// WithDetails 仅在 detail 非法时失败；回落无 detail 形态。
		return st.Err()
	}
	return st.Err()
}

// Stage 返回可直接进 interceptor.Assemble 的 ratelimit Stage。
func (l *Limiter) Stage() interceptor.Stage {
	return interceptor.RateLimitStage(l.Unary(), l.Stream())
}
