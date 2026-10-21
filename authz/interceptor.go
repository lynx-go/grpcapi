package authz

import (
	"context"
	"log/slog"

	"github.com/lynx-go/grpcapi/policy"
	"github.com/lynx-go/grpcapi/principal"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// StreamMode 是流式方法的默认授权粒度；per-operation StreamAuth 可覆盖。
type StreamMode int

const (
	// StreamModeOpen 在 stream 建立时授权一次（零值/默认）。
	StreamModeOpen StreamMode = iota
	// StreamModePerMessage 在每条 RecvMsg 后重新授权。
	StreamModePerMessage
)

// InterceptorOptions 是 authz 拦截器的配置。
type InterceptorOptions struct {
	MissingPrincipalCode codes.Code
	DeniedCode           codes.Code
	MissingPolicyCode    codes.Code
	StreamMode           StreamMode
	ResourceResolver     ResourceResolver
	OnDecision           func(ctx context.Context, op policy.Operation, d Decision)
	Logger               *slog.Logger
	// FrameworkExempt 豁免 health/reflection 等框架方法；nil = policy 默认。
	FrameworkExempt func(fullMethod string) bool
}

func (o InterceptorOptions) normalize() InterceptorOptions {
	if o.MissingPrincipalCode == codes.OK {
		o.MissingPrincipalCode = codes.Unauthenticated
	}
	if o.DeniedCode == codes.OK {
		o.DeniedCode = codes.PermissionDenied
	}
	if o.MissingPolicyCode == codes.OK {
		o.MissingPolicyCode = codes.Internal
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.FrameworkExempt == nil {
		o.FrameworkExempt = policy.DefaultFrameworkExempt
	}
	return o
}

// Options 是 gRPC 拦截器/HTTP 中间件共享的授权选项别名。
type Options = InterceptorOptions

// Interceptor 是 gRPC unary/stream 授权拦截器。
type Interceptor struct {
	set     *policy.Set
	decider Decider
	opts    InterceptorOptions
}

// NewInterceptor 构造拦截器；decider 为 nil 时使用 RequirementDecider。
func NewInterceptor(set *policy.Set, decider Decider, opts InterceptorOptions) (*Interceptor, error) {
	if set == nil {
		return nil, status.Error(codes.Internal, "authz: policy.Set is nil")
	}
	if decider == nil {
		var err error
		decider, err = NewRequirementDecider(set)
		if err != nil {
			return nil, err
		}
	}
	return &Interceptor{set: set, decider: decider, opts: opts.normalize()}, nil
}

// Unary 返回 unary 授权拦截器。
func (i *Interceptor) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		op, ok := i.set.Get(info.FullMethod)
		if !ok {
			if i.opts.FrameworkExempt(info.FullMethod) {
				return handler(ctx, req)
			}
			i.opts.Logger.ErrorContext(ctx, "authz: missing policy", "method", info.FullMethod)
			return nil, status.Error(i.opts.MissingPolicyCode, "no authorization policy for method")
		}
		d, err := i.authorize(ctx, op, req, false)
		if err != nil {
			return nil, err
		}
		if !d.Allow {
			return nil, i.deny(ctx, op, d)
		}
		return handler(ctx, req)
	}
}

// Stream 返回 stream 授权拦截器。
func (i *Interceptor) Stream() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		op, ok := i.set.Get(info.FullMethod)
		if !ok {
			if i.opts.FrameworkExempt(info.FullMethod) {
				return handler(srv, ss)
			}
			i.opts.Logger.ErrorContext(ss.Context(), "authz: missing policy", "method", info.FullMethod)
			return status.Error(i.opts.MissingPolicyCode, "no authorization policy for method")
		}
		mode, ok := streamMode(op, i.opts.StreamMode)
		if !ok {
			return status.Error(codes.Internal, "invalid stream authorization mode")
		}
		if mode == StreamModePerMessage {
			return handler(srv, &authzStream{ServerStream: ss, interceptor: i, op: op})
		}
		d, err := i.authorize(ss.Context(), op, nil, true)
		if err != nil {
			return err
		}
		if !d.Allow {
			return i.deny(ss.Context(), op, d)
		}
		return handler(srv, ss)
	}
}

func streamMode(op policy.Operation, def StreamMode) (StreamMode, bool) {
	switch op.StreamAuth {
	case policy.StreamAuthPerMessage:
		return StreamModePerMessage, true
	case policy.StreamAuthOpen:
		return StreamModeOpen, true
	case 0:
		if def == StreamModeOpen || def == StreamModePerMessage {
			return def, true
		}
	}
	return 0, false
}

func (i *Interceptor) authorize(ctx context.Context, op policy.Operation, req any, stream bool) (Decision, error) {
	ec := policy.EvalContext{
		Operation: op,
		Principal: principalFrom(ctx),
		Request:   req,
		Metadata:  metadataMap(ctx),
	}
	if i.opts.ResourceResolver != nil {
		resource, err := i.opts.ResourceResolver.Resolve(ctx, Request{EvalContext: ec, Stream: stream})
		if err != nil {
			i.opts.Logger.ErrorContext(ctx, "authz: resource resolution failed", "method", op.ID, "error", err)
			return Decision{}, status.Error(codes.Internal, "authorization resource resolution failed")
		}
		ec.Resource = resource
	}
	d, err := i.decider.Decide(ctx, Request{EvalContext: ec, Stream: stream})
	if err != nil {
		if st, ok := status.FromError(err); ok {
			return Decision{}, st.Err()
		}
		i.opts.Logger.ErrorContext(ctx, "authz: decision failed", "method", op.ID, "error", err)
		return Decision{}, status.Error(codes.Internal, "authorization decision failed")
	}
	if i.opts.OnDecision != nil {
		i.opts.OnDecision(ctx, op, d)
	}
	return d, nil
}

func (i *Interceptor) deny(ctx context.Context, op policy.Operation, d Decision) error {
	code := d.Code
	if code == codes.OK {
		if principalFrom(ctx) == nil && !op.Policy.Anonymous {
			code = i.opts.MissingPrincipalCode
		} else {
			code = i.opts.DeniedCode
		}
	}
	msg := "permission denied"
	switch code {
	case codes.Unauthenticated:
		msg = "unauthenticated"
	case codes.Internal:
		msg = "internal server error"
	}
	i.opts.Logger.WarnContext(ctx, "authz: denied", "method", op.ID, "code", code.String(), "reason", d.Reason)
	return status.Error(code, msg)
}

type authzStream struct {
	grpc.ServerStream
	interceptor *Interceptor
	op          policy.Operation
}

func (s *authzStream) RecvMsg(m any) error {
	if err := s.ServerStream.RecvMsg(m); err != nil {
		return err
	}
	d, err := s.interceptor.authorize(s.Context(), s.op, m, true)
	if err != nil {
		return err
	}
	if !d.Allow {
		return s.interceptor.deny(s.Context(), s.op, d)
	}
	return nil
}

func principalFrom(ctx context.Context) *principal.Principal {
	p, _ := principal.From(ctx)
	return p
}

func metadataMap(ctx context.Context) map[string][]string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok || len(md) == 0 {
		return nil
	}
	out := make(map[string][]string, len(md))
	for k, vs := range md {
		out[k] = append([]string(nil), vs...)
	}
	return out
}
