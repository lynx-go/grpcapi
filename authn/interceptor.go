package authn

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/lynx-go/grpcapi/gateway"
	"github.com/lynx-go/grpcapi/principal"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// MultipleCredentialPolicy 是同一请求出现多种凭证时的策略。
type MultipleCredentialPolicy int

const (
	// MultipleCredentialReject 是默认：多种凭证一律拒绝。
	MultipleCredentialReject MultipleCredentialPolicy = iota
	// MultipleCredentialFirstWins 只使用第一个出现的凭证族。
	MultipleCredentialFirstWins
)

// InvalidCredentialPolicy 是无效凭证的处理策略。
type InvalidCredentialPolicy int

const (
	// InvalidCredentialReject 是默认：即使 public 方法也返回 401。
	InvalidCredentialReject InvalidCredentialPolicy = iota
	// InvalidCredentialIgnoreOnAnonymous 对显式 public 方法忽略无效凭证。
	InvalidCredentialIgnoreOnAnonymous
)

// Options 是认证拦截器的配置。
type Options struct {
	MultipleCredentialPolicy MultipleCredentialPolicy
	InvalidCredentialPolicy  InvalidCredentialPolicy
	// IsAnonymous 用于 IgnoreOnAnonymous；nil = 一律不忽略。
	IsAnonymous func(fullMethod string) bool
	Extractor   Extractor
	Enrichers   []Enricher
	OnFailure   func(ctx context.Context, err error)
	Logger      *slog.Logger
}

func (o Options) normalize() Options {
	if o.Extractor == nil {
		o.Extractor = DefaultExtractor()
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return o
}

// Interceptor 是 gRPC + HTTP 认证拦截器。
type Interceptor struct {
	chain Chain
	opts  Options
}

// New 构造认证拦截器。
func New(chain Chain, opts Options) *Interceptor {
	return &Interceptor{chain: chain, opts: opts.normalize()}
}

// Unary 返回 unary 认证拦截器。
func (i *Interceptor) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		pr, _ := peer.FromContext(ctx)
		creds, err := i.opts.Extractor.Extract(ctx, info.FullMethod, md, pr)
		if err != nil {
			i.fail(ctx, err)
			return nil, status.Error(codes.Unauthenticated, "invalid credentials")
		}
		p, err := i.authenticate(ctx, info.FullMethod, i.isAnonymous(info.FullMethod), creds)
		if err != nil {
			return nil, err
		}
		if p != nil {
			ctx = principal.With(ctx, p)
		}
		return handler(ctx, req)
	}
}

// Stream 返回 stream 认证拦截器。
func (i *Interceptor) Stream() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := ss.Context()
		md, _ := metadata.FromIncomingContext(ctx)
		pr, _ := peer.FromContext(ctx)
		creds, err := i.opts.Extractor.Extract(ctx, info.FullMethod, md, pr)
		if err != nil {
			i.fail(ctx, err)
			return status.Error(codes.Unauthenticated, "invalid credentials")
		}
		p, err := i.authenticate(ctx, info.FullMethod, i.isAnonymous(info.FullMethod), creds)
		if err != nil {
			return err
		}
		if p != nil {
			ctx = principal.With(ctx, p)
		}
		return handler(srv, &authStream{ServerStream: ss, ctx: ctx})
	}
}

// HTTPOptions 是 HTTP 认证中间件的配置。
type HTTPOptions struct {
	Anonymous   bool
	Extractor   HTTPExtractor
	ErrorWriter ErrorWriter
}

// ErrorWriter 把认证错误写到 HTTP 响应。
type ErrorWriter func(w http.ResponseWriter, r *http.Request, err error)

// HTTPMiddleware 对已知 route 做认证；extra route 由 server 调用。
func (i *Interceptor) HTTPMiddleware(fullMethod string, opts HTTPOptions) func(http.Handler) http.Handler {
	extractor := opts.Extractor
	if extractor == nil {
		extractor = DefaultHTTPExtractor()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			creds, err := extractor.ExtractHTTP(r.Context(), fullMethod, r)
			if err != nil {
				i.fail(r.Context(), err)
				writeHTTPError(w, r, status.Error(codes.Unauthenticated, "invalid credentials"), opts)
				return
			}
			p, err := i.authenticate(r.Context(), fullMethod, opts.Anonymous, creds)
			if err != nil {
				writeHTTPError(w, r, err, opts)
				return
			}
			if p != nil {
				r = r.WithContext(principal.With(r.Context(), p))
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (i *Interceptor) authenticate(ctx context.Context, fullMethod string, anonymous bool, creds Credentials) (*principal.Principal, error) {
	if creds.Empty() {
		return nil, nil
	}
	// 同一凭证族出现多个值（尤其多个 Authorization）一律拒绝，避免代理
	// 叠加/注入时由“取第一个”静默选出攻击者可控的凭证。
	if len(creds.Bearer) > 1 || len(creds.APIKeys) > 1 {
		err := status.Error(codes.Unauthenticated, "multiple credentials of the same type are not allowed")
		i.fail(ctx, err)
		return nil, err
	}
	if i.opts.MultipleCredentialPolicy == MultipleCredentialReject && creds.AuthKinds() > 1 {
		err := status.Error(codes.Unauthenticated, "multiple credential types are not allowed")
		i.fail(ctx, err)
		return nil, err
	}
	p, err := i.chain.Authenticate(ctx, creds)
	if err != nil {
		if i.ignoreInvalid(anonymous, err) {
			return nil, nil
		}
		i.fail(ctx, err)
		return nil, normalizeAuthError(err)
	}
	if p == nil {
		err := status.Error(codes.Unauthenticated, "unrecognized credentials")
		i.fail(ctx, err)
		return nil, err
	}
	for _, e := range i.opts.Enrichers {
		if e == nil {
			continue
		}
		if err := e.Enrich(ctx, p); err != nil {
			i.fail(ctx, err)
			return nil, normalizeAuthError(err)
		}
	}
	return p, nil
}

func (i *Interceptor) ignoreInvalid(anonymous bool, err error) bool {
	if i.opts.InvalidCredentialPolicy != InvalidCredentialIgnoreOnAnonymous {
		return false
	}
	return anonymous && status.Code(err) == codes.Unauthenticated
}

func (i *Interceptor) isAnonymous(fullMethod string) bool {
	return i.opts.IsAnonymous != nil && i.opts.IsAnonymous(fullMethod)
}

func (i *Interceptor) fail(ctx context.Context, err error) {
	i.opts.Logger.WarnContext(ctx, "authn: authentication failed", "error", err)
	if i.opts.OnFailure != nil {
		i.opts.OnFailure(ctx, err)
	}
}

func normalizeAuthError(err error) error {
	if st, ok := status.FromError(err); ok {
		return st.Err()
	}
	// 认证器未使用 status 时按凭证错误处理；参考实现均返回显式 status。
	return status.Error(codes.Unauthenticated, "invalid credentials")
}

func writeHTTPError(w http.ResponseWriter, r *http.Request, err error, opts HTTPOptions) {
	if opts.ErrorWriter != nil {
		opts.ErrorWriter(w, r, err)
		return
	}
	code := status.Code(err)
	// 与 gateway 共用同一映射（GENERALIZATION：错误统一走 gateway 语义），
	// 不再维护会漂移的私有副本。
	http.Error(w, strings.ToLower(code.String()), gateway.DefaultCodeToHTTP(code))
}

type authStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *authStream) Context() context.Context { return s.ctx }
