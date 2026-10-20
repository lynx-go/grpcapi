package authz

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/lynx-go/grpcapi/policy"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrorWriter 把授权错误写到 HTTP 响应；server 会注入 gateway.ErrorWriter，
// 保证 extra route 与 gateway 的错误体一致。
type ErrorWriter func(w http.ResponseWriter, r *http.Request, err error)

// OperationResolver 用于动态路由（如挂载第三方 router）按请求查 operation。
type OperationResolver func(*http.Request) (policy.Operation, bool)

// HTTPOptions 是 HTTP 授权中间件的配置。
type HTTPOptions struct {
	ResourceResolver ResourceResolver
	ErrorWriter      ErrorWriter
	OnDecision       func(ctx context.Context, op policy.Operation, d Decision)
	Logger           *slog.Logger
}

func (o HTTPOptions) logger() *slog.Logger {
	if o.Logger != nil {
		return o.Logger
	}
	return slog.Default()
}

// HTTPMiddleware 对已知 operation 的 extra route 做授权。
// 注意：proto 路由由 gRPC 拦截器授权，不要再套这一层，避免双重决策。
func HTTPMiddleware(decider Decider, op policy.Operation, opts HTTPOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if decider == nil {
				opts.logger().ErrorContext(r.Context(), "authz: nil decider", "route", op.ID)
				writeHTTPError(w, r, status.Error(codes.Internal, "authorization unavailable"), opts)
				return
			}
			ec := policy.EvalContext{
				Operation: op,
				Principal: principalFrom(r.Context()),
				Request:   r,
				Metadata:  headerMap(r.Header),
			}
			if opts.ResourceResolver != nil {
				resource, err := opts.ResourceResolver.Resolve(r.Context(), Request{EvalContext: ec})
				if err != nil {
					opts.logger().ErrorContext(r.Context(), "authz: resource resolution failed", "route", op.ID, "error", err)
					writeHTTPError(w, r, status.Error(codes.Internal, "authorization resource resolution failed"), opts)
					return
				}
				ec.Resource = resource
			}
			d, err := decider.Decide(r.Context(), Request{EvalContext: ec})
			if err != nil {
				if st, ok := status.FromError(err); ok {
					writeHTTPError(w, r, st.Err(), opts)
					return
				}
				opts.logger().ErrorContext(r.Context(), "authz: decision failed", "route", op.ID, "error", err)
				writeHTTPError(w, r, status.Error(codes.Internal, "authorization decision failed"), opts)
				return
			}
			if opts.OnDecision != nil {
				opts.OnDecision(r.Context(), op, d)
			}
			if d.Allow {
				next.ServeHTTP(w, r)
				return
			}
			code := d.Code
			if code == codes.OK {
				if ec.Principal == nil && !op.Policy.Anonymous {
					code = codes.Unauthenticated
				} else {
					code = codes.PermissionDenied
				}
			}
			msg := "permission denied"
			if code == codes.Unauthenticated {
				msg = "unauthenticated"
			}
			opts.logger().WarnContext(r.Context(), "authz: denied", "route", op.ID, "code", code.String(), "reason", d.Reason)
			writeHTTPError(w, r, status.Error(code, msg), opts)
		})
	}
}

// HTTPMiddlewareFor 按 resolver 动态查找 operation；适合挂载第三方 router。
func HTTPMiddlewareFor(set *policy.Set, decider Decider, resolve OperationResolver, opts HTTPOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if set == nil || resolve == nil {
				writeHTTPError(w, r, status.Error(codes.Internal, "authorization unavailable"), opts)
				return
			}
			op, ok := resolve(r)
			if !ok {
				opts.logger().ErrorContext(r.Context(), "authz: cannot resolve operation", "method", r.Method, "path", r.URL.Path)
				writeHTTPError(w, r, status.Error(codes.Internal, "no authorization policy for route"), opts)
				return
			}
			HTTPMiddleware(decider, op, opts)(next).ServeHTTP(w, r)
		})
	}
}

func headerMap(h http.Header) map[string][]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string][]string, len(h))
	for k, vs := range h {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

func writeHTTPError(w http.ResponseWriter, r *http.Request, err error, opts HTTPOptions) {
	if opts.ErrorWriter != nil {
		opts.ErrorWriter(w, r, err)
		return
	}
	code := status.Code(err)
	msg := status.Convert(err).Message()
	if msg == "" {
		msg = http.StatusText(httpStatusForCode(code))
	}
	http.Error(w, msg, httpStatusForCode(code))
}

func httpStatusForCode(code codes.Code) int {
	switch code {
	case codes.Unauthenticated:
		return http.StatusUnauthorized
	case codes.PermissionDenied:
		return http.StatusForbidden
	case codes.Unavailable:
		return http.StatusServiceUnavailable
	case codes.DeadlineExceeded:
		return http.StatusGatewayTimeout
	case codes.ResourceExhausted:
		return http.StatusTooManyRequests
	case codes.InvalidArgument:
		return http.StatusBadRequest
	case codes.NotFound:
		return http.StatusNotFound
	default:
		return http.StatusInternalServerError
	}
}
