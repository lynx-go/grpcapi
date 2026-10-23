package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lynx-go/grpcapi/authn"
	"github.com/lynx-go/grpcapi/authz"
	"github.com/lynx-go/grpcapi/cors"
	"github.com/lynx-go/grpcapi/csrf"
	"github.com/lynx-go/grpcapi/gateway"
	"github.com/lynx-go/grpcapi/interceptor"
	"github.com/lynx-go/grpcapi/policy"
	"github.com/lynx-go/grpcapi/policy/protopolicy"
	"github.com/lynx-go/grpcapi/surface"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Config 是 server.New 的输入。零值安全：只给 Policy + Services 也能跑本地 dev。
type Config struct {
	// Policy 与 PolicySource 二选一；仅 ExtraRoute 时两者都可为空。
	Policy        *policy.Set
	PolicySource  policy.Source
	PolicyOptions policy.Options

	Services []Registration
	APIs     []APIConfig

	GRPCAddr    string
	HTTPAddr    string
	DisableGRPC bool
	DisableHTTP bool
	TLS         *tls.Config

	// GRPCOptions 应用于 external server（无独立 internal 时也应用于单
	// server）。非空时内部 gateway 使用独立的 plaintext server，避免把
	// grpc.Creds 等传输选项带到 bufconn。
	GRPCOptions []grpc.ServerOption
	// InternalGRPCOptions 只用于独立 plaintext internal server（TLS 或
	// GRPCOptions 非空时）。不要把 grpc.Creds 放这里，否则 bufconn gateway
	// 会握手失败。
	InternalGRPCOptions   []grpc.ServerOption
	MaxRecvMsgSize        int
	MaxSendMsgSize        int
	HTTPReadHeaderTimeout time.Duration
	HTTPReadTimeout       time.Duration
	HTTPWriteTimeout      time.Duration
	HTTPIdleTimeout       time.Duration

	// HTTPBodyLimitBytes 是 proto 路由(gateway)与全局 HTTP 请求体上限。
	// 0 = 与 MaxRecvMsgSize 同源（DESIGN §5.16 安全默认：HTTP 侧 protojson
	// 解码不受 gRPC 消息上限保护）；>0 显式解耦两种语义（如小消息 API +
	// 大文件上传的混合负载）。逐路由放宽用 ExtraRoute.MaxBodyBytes。
	// 负值启动失败。
	HTTPBodyLimitBytes int64

	// NetworkDial 为 true 时 gateway 走 cfg.GRPCAddr；默认 in-process bufconn。
	NetworkDial bool
	Dial        gateway.DialConfig

	TrustedProxies            []string
	Authenticators            authn.Chain
	AuthnOptions              authn.Options
	AllowNoAuthenticator      bool
	AllowNoAuthz              bool
	AllowNoCSRF               bool
	AllowUnregisteredPolicies bool
	Decider                   authz.Decider
	AuthzOptions              authz.Options
	Chain                     *interceptor.Chain

	Mux            gateway.MuxOptions
	ExtraRoutes    []ExtraRoute
	HTTPMiddleware []func(http.Handler) http.Handler
	CSRF           *csrf.Config
	// CORS 是全局跨源中间件；nil = 不启用（不放行任何跨源）。按 API 面
	// 配置时用 APIConfig.Middleware 挂 cors.New。预检请求在 CSRF/body
	// limit 之外短路。
	CORS *cors.Config

	DisableHealth bool
	Readiness     func(ctx context.Context) error
	AccessLog     bool
	Reflection    bool
	Docs          fs.FS

	Logger          *slog.Logger
	ShutdownTimeout time.Duration
}

type Server struct {
	cfg            Config
	logger         *slog.Logger
	set            *policy.Set
	surf           *surface.Surface
	chain          *interceptor.Chain
	externalServer *grpc.Server
	internalServer *grpc.Server
	health         *health.Server
	httpServer     *http.Server
	handler        http.Handler
	conn           *grpc.ClientConn
	bufLis         *bufconn.Listener
	routes         []surface.RouteInfo
	ops            []policy.Operation
	serveOnce      sync.Once

	mu       sync.Mutex
	grpcAddr string
	httpAddr string
}

type apiGroup struct {
	name       string
	prefix     string
	middleware []func(http.Handler) http.Handler
	mux        gateway.MuxOptions
	docs       fs.FS
	regs       []Registration
}

// New 构建 gRPC + gateway + HTTP 装配，但不启动监听。
func New(ctx context.Context, cfg Config) (*Server, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.MaxRecvMsgSize == 0 {
		cfg.MaxRecvMsgSize = 8 << 20
	}
	if cfg.MaxSendMsgSize == 0 {
		cfg.MaxSendMsgSize = 8 << 20
	}
	if cfg.HTTPReadHeaderTimeout == 0 {
		cfg.HTTPReadHeaderTimeout = 10 * time.Second
	}
	if cfg.HTTPIdleTimeout == 0 {
		cfg.HTTPIdleTimeout = 120 * time.Second
	}
	if cfg.DisableGRPC && cfg.DisableHTTP {
		return nil, fmt.Errorf("server: DisableGRPC and DisableHTTP cannot both be true")
	}
	if cfg.HTTPBodyLimitBytes < 0 {
		return nil, fmt.Errorf("server: HTTPBodyLimitBytes cannot be negative")
	}
	if cfg.NetworkDial && strings.HasSuffix(cfg.GRPCAddr, ":0") {
		return nil, fmt.Errorf("server: NetworkDial cannot use an ephemeral gRPC port")
	}
	if cfg.NetworkDial && len(cfg.TrustedProxies) == 0 {
		// gateway 与 gRPC 同机时，回环地址就是可信代理。
		cfg.TrustedProxies = []string{"127.0.0.1/32", "::1/128"}
	}
	if cfg.DisableHTTP && (len(cfg.ExtraRoutes) > 0 || cfg.Docs != nil || len(cfg.APIs) > 0 || len(cfg.HTTPMiddleware) > 0 || cfg.CSRF != nil || cfg.CORS != nil) {
		return nil, fmt.Errorf("server: DisableHTTP cannot be combined with extra routes/docs/API configs/HTTP middleware/CSRF/CORS")
	}

	regs := allRegistrations(cfg)
	set, err := buildPolicy(ctx, cfg, regs)
	if err != nil {
		return nil, err
	}

	extra := append([]ExtraRoute(nil), cfg.ExtraRoutes...)
	extra = append(extra, builtinRoutes(cfg)...)
	var extraOps []policy.Operation
	for _, r := range extra {
		op, err := r.operation()
		if err != nil {
			return nil, err
		}
		extraOps = append(extraOps, op)
	}
	set, err = set.WithOperations(extraOps...)
	if err != nil {
		return nil, fmt.Errorf("server: extra routes: %w", err)
	}

	descriptors, err := uniqueServiceDescriptors(regs)
	if err != nil {
		return nil, err
	}
	surf, err := surface.BuildFromServices(descriptors, set)
	if err != nil {
		return nil, err
	}

	if err := validateRegistrations(cfg, surf, regs); err != nil {
		return nil, err
	}
	if err := validateRegisteredPolicies(cfg, set, surf, extraOps); err != nil {
		return nil, err
	}
	if err := validateExtraConflicts(cfg, surf, extraOps); err != nil {
		return nil, err
	}
	if err := validateCSRF(cfg); err != nil {
		return nil, err
	}

	decider := cfg.Decider
	if decider == nil {
		decider, err = authz.NewRequirementDecider(set)
		if err != nil {
			return nil, err
		}
	}
	authorizer, err := authz.NewInterceptor(set, decider, cfg.AuthzOptions)
	if err != nil {
		return nil, err
	}
	authnOpts := cfg.AuthnOptions
	if authnOpts.IsAnonymous == nil {
		authnOpts.IsAnonymous = set.IsAnonymous
	}
	authenticator := authn.New(cfg.Authenticators, authnOpts)

	chain := cfg.Chain
	if chain == nil {
		chain, err = interceptor.Assemble(
			interceptor.RecoveryStage(interceptor.RecoveryOptions{Logger: cfg.Logger}),
			interceptor.RequestIDStage(interceptor.RequestIDOptions{Logger: cfg.Logger}),
			interceptor.ClientInfoStage(interceptor.NewClientInfo(interceptor.ClientInfoConfig{TrustedProxies: cfg.TrustedProxies})),
			interceptor.AuthnStage(authenticator.Unary(), authenticator.Stream()),
			interceptor.AuthzStage(authorizer.Unary(), authorizer.Stream()),
			interceptor.ValidateStage(interceptor.NewValidate()),
		)
		if err != nil {
			return nil, err
		}
	}
	if err := validateAuthChain(cfg, chain, set); err != nil {
		return nil, err
	}

	srv := &Server{
		cfg:    cfg,
		logger: cfg.Logger,
		set:    set,
		surf:   surf,
		chain:  chain,
		ops:    set.Operations(),
	}

	if err := srv.buildGRPC(); err != nil {
		return nil, err
	}
	handler, routes, err := srv.buildHTTP(ctx, set, surf, extra, extraOps, decider, authenticator)
	if err != nil {
		return nil, err
	}
	srv.handler = handler
	srv.routes = routes
	return srv, nil
}

func buildPolicy(ctx context.Context, cfg Config, regs []Registration) (*policy.Set, error) {
	if cfg.Policy != nil && cfg.PolicySource != nil {
		return nil, fmt.Errorf("server: Policy and PolicySource are mutually exclusive")
	}
	if cfg.Policy != nil {
		return cfg.Policy, nil
	}
	if cfg.PolicySource == nil {
		if len(regs) > 0 {
			return nil, fmt.Errorf("server: Policy or PolicySource is required for registered services")
		}
		return policy.NewSet()
	}
	opts := cfg.PolicyOptions
	if opts.Provider == nil {
		opts.Provider = protopolicy.New(protopolicy.Options{})
	}
	if opts.Registry == nil {
		opts.Registry = policy.DefaultRegistry()
	}
	if len(opts.IncludeServices) == 0 {
		for _, r := range regs {
			if r.Descriptor != nil {
				opts.IncludeServices = append(opts.IncludeServices, r.Descriptor.FullName())
			}
		}
	}
	return policy.Build(ctx, cfg.PolicySource, opts)
}

func (s *Server) buildGRPC() error {
	if !s.cfg.DisableHealth {
		s.health = health.NewServer()
	}
	if !s.cfg.DisableGRPC {
		s.externalServer = s.newGRPCServer(true)
		s.registerGRPC(s.externalServer)
	}
	if !s.cfg.DisableHTTP {
		// TLS/Creds 外部 server 不能同时服务明文 bufconn；用独立的内部
		// server。GRPCOptions 可能包含 grpc.Creds，因此非空时也不共用。
		if s.cfg.TLS == nil && len(s.cfg.GRPCOptions) == 0 && s.externalServer != nil {
			s.internalServer = s.externalServer
		} else {
			s.internalServer = s.newGRPCServer(false)
			s.registerGRPC(s.internalServer)
		}
	}
	return nil
}

func (s *Server) newGRPCServer(withTLS bool) *grpc.Server {
	opts := make([]grpc.ServerOption, 0, len(s.cfg.GRPCOptions)+4)
	if withTLS && s.cfg.TLS != nil {
		opts = append(opts, grpc.Creds(credentials.NewTLS(s.cfg.TLS)))
	}
	opts = append(opts,
		grpc.MaxRecvMsgSize(s.cfg.MaxRecvMsgSize),
		grpc.MaxSendMsgSize(s.cfg.MaxSendMsgSize),
	)
	opts = append(opts, s.chain.ServerOptions()...)
	if withTLS {
		opts = append(opts, s.cfg.GRPCOptions...)
	} else {
		opts = append(opts, s.cfg.InternalGRPCOptions...)
	}
	return grpc.NewServer(opts...)
}

func (s *Server) registerGRPC(srv *grpc.Server) {
	seen := make(map[string]struct{})
	for _, r := range allRegistrations(s.cfg) {
		if r.Descriptor == nil || r.RegisterGRPC == nil {
			continue
		}
		name := string(r.Descriptor.FullName())
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		r.RegisterGRPC(srv)
	}
	if s.health != nil {
		healthpb.RegisterHealthServer(srv, s.health)
	}
	if s.cfg.Reflection {
		reflection.Register(srv)
	}
}

func (s *Server) buildHTTP(ctx context.Context, set *policy.Set, surf *surface.Surface, extra []ExtraRoute, extraOps []policy.Operation, decider authz.Decider, authenticator *authn.Interceptor) (http.Handler, []surface.RouteInfo, error) {
	if s.cfg.DisableHTTP {
		return nil, surf.Routes(), nil
	}
	// 全局 HTTP 请求体上限：默认与 MaxRecvMsgSize 同源（DESIGN §5.16），可经
	// HTTPBodyLimitBytes 显式解耦；extra route 可用 MaxBodyBytes 逐路由放宽。
	bodyLimit := int64(s.cfg.MaxRecvMsgSize)
	if s.cfg.HTTPBodyLimitBytes > 0 {
		bodyLimit = s.cfg.HTTPBodyLimitBytes
	}

	groups, err := s.buildGroups(surf)
	if err != nil {
		return nil, nil, err
	}

	var conn grpc.ClientConnInterface
	if s.cfg.NetworkDial {
		cfg := s.cfg.Dial
		if cfg.TLS == nil && s.cfg.TLS != nil {
			// Config.TLS 是服务端配置；只复制客户端需要的信任字段，绝不
			// 把 Certificates/ClientAuth 当成客户端凭证。
			cfg.TLS = &tls.Config{
				RootCAs:    s.cfg.TLS.RootCAs,
				ServerName: s.cfg.TLS.ServerName,
				MinVersion: s.cfg.TLS.MinVersion,
			}
		}
		conn, err = gateway.Dial(ctx, s.cfg.GRPCAddr, cfg)
		if err != nil {
			return nil, nil, err
		}
		s.conn = conn.(*grpc.ClientConn)
	} else {
		s.bufLis = bufconn.Listen(1 << 20)
		s.conn, err = grpc.NewClient("passthrough:///bufnet",
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
				return s.bufLis.DialContext(ctx)
			}),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		if err != nil {
			return nil, nil, err
		}
		conn = s.conn
	}

	trusted, err := interceptor.ParseTrustedProxies(s.cfg.TrustedProxies)
	if err != nil {
		return nil, nil, fmt.Errorf("server: trusted proxies: %w", err)
	}
	clientIPAnnotator := func(_ context.Context, r *http.Request) metadata.MD {
		peerIP := interceptor.PeerIPFromAddr(r.RemoteAddr)
		ip := trusted.ResolveClientIP(peerIP, r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Real-IP"))
		if ip == "" {
			return nil
		}
		// 解析结果同时以标准 XFF 形态下发：clientinfo 对合法 TCP peer
		// 不再采信 x-grpcapi-client-ip（直连 gRPC 客户端可自设该键），
		// 而是从该 XFF 右起回溯还原同一 IP；bufconn 路径 peer 非 IP，
		// 仍走注入键。
		return metadata.Pairs("x-grpcapi-client-ip", ip, "x-forwarded-for", ip)
	}

	root := http.NewServeMux()
	encoder := gateway.DefaultErrorEncoder(gateway.ErrorOptions{Logger: s.logger})
	if s.cfg.Mux.ErrorEncoder != nil {
		encoder = s.cfg.Mux.ErrorEncoder
	}
	globalErr := gateway.NewEncoderErrorHandler(encoder)
	errorWriter := func(w http.ResponseWriter, r *http.Request, err error) {
		globalErr(r.Context(), nil, gateway.NewMarshaler(), w, r, err)
	}

	for _, g := range groups {
		muxOpts := g.mux
		if muxOpts.ErrorEncoder == nil {
			muxOpts.ErrorEncoder = encoder
		}
		projectMeta := muxOpts.Metadata
		muxOpts.Metadata = func(ctx context.Context, r *http.Request) metadata.MD {
			var md metadata.MD
			if projectMeta != nil {
				md = projectMeta(ctx, r)
			}
			// 可信 client-ip 最后追加，确保 project metadata 不能覆盖
			// （clientinfo 取最后一个值）。
			ipmd := clientIPAnnotator(ctx, r)
			if len(ipmd) > 0 {
				if md == nil {
					md = metadata.MD{}
				}
				for k, vs := range ipmd {
					md[k] = append(md[k], vs...)
				}
			}
			return md
		}
		mux := gateway.NewMux(muxOpts)
		var fns []gateway.RegisterFunc
		for _, r := range g.regs {
			if r.RegisterHTTP == nil {
				continue
			}
			fns = append(fns, gateway.RegisterFunc(r.RegisterHTTP))
		}
		if len(fns) > 0 {
			if err := gateway.Register(ctx, mux, conn, fns...); err != nil {
				return nil, nil, err
			}
		}
		var h http.Handler = mux
		for i := len(g.middleware) - 1; i >= 0; i-- {
			h = g.middleware[i](h)
		}
		// proto 路由统一按全局上限限制请求体（本组 middleware 之外、挂载
		// 之内），不做逐路由豁免；大 body 场景走 extra route。
		h = withBodyLimit(h, bodyLimit)
		pattern := g.prefix
		if pattern == "" {
			pattern = "/"
		} else {
			pattern = strings.TrimRight(pattern, "/") + "/"
			h = http.StripPrefix(strings.TrimRight(g.prefix, "/"), h)
		}
		if err := safeHandle(root, pattern, h); err != nil {
			return nil, nil, err
		}
		if g.docs != nil {
			docsPattern := joinPaths("/docs", g.name) + "/"
			if err := safeHandle(root, "GET "+docsPattern, http.StripPrefix(docsPattern, http.FileServer(http.FS(g.docs)))); err != nil {
				return nil, nil, err
			}
		}
	}

	for i, r := range extra {
		limit := bodyLimit
		if r.MaxBodyBytes > 0 {
			limit = r.MaxBodyBytes
		}
		h := r.Handler
		h = withBodyLimit(h, limit)
		h = authz.HTTPMiddleware(decider, extraOps[i], authz.HTTPOptions{
			ResourceResolver: s.cfg.AuthzOptions.ResourceResolver,
			OnDecision:       s.cfg.AuthzOptions.OnDecision,
			ErrorWriter:      errorWriter,
			Logger:           s.logger,
		})(h)
		h = authenticator.HTTPMiddleware(extraOps[i].ID, authn.HTTPOptions{
			Anonymous:   extraOps[i].Policy.Anonymous,
			ErrorWriter: errorWriter,
		})(h)
		if err := safeHandle(root, r.Method+" "+r.Path, h); err != nil {
			return nil, nil, err
		}
	}

	if s.cfg.Docs != nil {
		if err := safeHandle(root, "GET /docs/", withBodyLimit(http.StripPrefix("/docs/", http.FileServer(http.FS(s.cfg.Docs))), bodyLimit)); err != nil {
			return nil, nil, err
		}
	}

	var h http.Handler = root
	for i := len(s.cfg.HTTPMiddleware) - 1; i >= 0; i-- {
		h = s.cfg.HTTPMiddleware[i](h)
	}
	if s.cfg.CSRF != nil {
		h = csrf.New(*s.cfg.CSRF).Handler(h)
	}
	if s.cfg.AccessLog {
		h = accessLog(s.logger, h)
	}
	// CORS 放最外层：预检请求不进入 CSRF/业务中间件，也不进 access log。
	if s.cfg.CORS != nil {
		mw, err := cors.New(*s.cfg.CORS)
		if err != nil {
			return nil, nil, fmt.Errorf("server: %w", err)
		}
		h = mw.Handler(h)
	}

	routes := prefixedRoutes(surf, groups, s.cfg)
	for i, op := range extraOps {
		routes = append(routes, surface.RouteInfo{
			ID:       op.ID,
			Method:   extra[i].Method,
			Path:     extra[i].Path,
			API:      op.API,
			Exposure: op.Exposure,
			Label:    op.EffectiveLabel(),
			Source:   "extra",
		})
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Path != routes[j].Path {
			return routes[i].Path < routes[j].Path
		}
		return routes[i].Method < routes[j].Method
	})

	s.httpServer = &http.Server{
		Handler:           h,
		ReadHeaderTimeout: s.cfg.HTTPReadHeaderTimeout,
		ReadTimeout:       s.cfg.HTTPReadTimeout,
		WriteTimeout:      s.cfg.HTTPWriteTimeout,
		IdleTimeout:       s.cfg.HTTPIdleTimeout,
	}
	return h, routes, nil
}

func (s *Server) buildGroups(surf *surface.Surface) ([]*apiGroup, error) {
	groups := map[string]*apiGroup{}
	for _, a := range s.cfg.APIs {
		if a.Name == "" {
			return nil, fmt.Errorf("server: APIConfig with empty name")
		}
		if _, dup := groups[a.Name]; dup {
			return nil, fmt.Errorf("server: duplicate APIConfig %q", a.Name)
		}
		prefix := strings.TrimSpace(a.Prefix)
		if prefix != "" {
			prefix = surface.NormalizePath(prefix)
			if prefix == "/" {
				prefix = ""
			}
		}
		groups[a.Name] = &apiGroup{
			name: a.Name, prefix: prefix,
			middleware: a.Middleware, mux: a.Mux, docs: a.Docs,
		}
	}

	apiByService := make(map[string]string)
	for _, op := range surf.Operations() {
		apiByService[op.Operation.Service] = op.Operation.API
	}
	needsDefault := false
	seenHTTP := make(map[string]struct{})
	for _, r := range allRegistrations(s.cfg) {
		if r.Descriptor == nil {
			continue
		}
		api := r.API
		derived := apiByService[string(r.Descriptor.FullName())]
		if api == "" {
			api = derived
		}
		if api == "" {
			needsDefault = true
		}
		if api != "" && derived != "" && api != derived && !r.AllowAPIMismatch {
			return nil, fmt.Errorf("server: service %s registered to API %q but proto declares %q", r.Descriptor.FullName(), api, derived)
		}
		key := api + "|" + string(r.Descriptor.FullName())
		if _, dup := seenHTTP[key]; dup {
			continue
		}
		seenHTTP[key] = struct{}{}
		g, ok := groups[api]
		if !ok {
			g = &apiGroup{name: api}
			groups[api] = g
		}
		g.regs = append(g.regs, r)
	}
	if needsDefault {
		if _, ok := groups[""]; !ok {
			groups[""] = &apiGroup{}
		}
	}
	seenPrefix := make(map[string]string, len(groups))
	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if other, dup := seenPrefix[groups[name].prefix]; dup {
			return nil, fmt.Errorf("server: API groups %q and %q share prefix %q", other, name, groups[name].prefix)
		}
		seenPrefix[groups[name].prefix] = name
	}
	// 前缀遮蔽（GENERALIZATION §5.16「Prefix 不互相遮蔽」）：/v1 与
	// /v1/admin 会让后一面的路由落在前一面的前缀之下，face 隔离失效。
	// 边界按 path 段判定（/v1 与 /v1admin 不算遮蔽）；空串是默认面，
	// 不参与。
	for _, a := range names {
		for _, b := range names {
			if a == b {
				continue
			}
			pa, pb := groups[a].prefix, groups[b].prefix
			if pa == "" || pb == "" {
				continue
			}
			if strings.HasPrefix(pa, pb+"/") {
				return nil, fmt.Errorf("server: API group %q prefix %q is shadowed by %q prefix %q", a, pa, b, pb)
			}
		}
	}
	out := make([]*apiGroup, 0, len(groups))
	for _, g := range groups {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, nil
}

func prefixedRoutes(surf *surface.Surface, groups []*apiGroup, cfg Config) []surface.RouteInfo {
	prefixByAPI := make(map[string]string, len(groups))
	for _, g := range groups {
		prefixByAPI[g.name] = g.prefix
	}
	routes := surf.Routes()
	for i := range routes {
		routes[i].Path = joinPaths(prefixByAPI[routes[i].API], routes[i].ProtoPath)
	}
	return routes
}

func allRegistrations(cfg Config) []Registration {
	out := append([]Registration(nil), cfg.Services...)
	for _, a := range cfg.APIs {
		for _, r := range a.Services {
			if r.API == "" {
				r.API = a.Name
			}
			out = append(out, r)
		}
	}
	return out
}

func uniqueServiceDescriptors(regs []Registration) ([]protoreflect.ServiceDescriptor, error) {
	seen := make(map[string]struct{})
	var out []protoreflect.ServiceDescriptor
	for _, r := range regs {
		if r.Descriptor == nil {
			return nil, fmt.Errorf("server: registration with nil descriptor")
		}
		name := string(r.Descriptor.FullName())
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, r.Descriptor)
	}
	return out, nil
}

func validateRegistrations(cfg Config, surf *surface.Surface, regs []Registration) error {
	httpServices := make(map[string]bool)
	for _, op := range surf.Operations() {
		if len(op.HTTP) > 0 {
			httpServices[op.Operation.Service] = true
		}
	}
	for _, r := range regs {
		if r.Descriptor == nil {
			return fmt.Errorf("server: registration with nil descriptor")
		}
		if r.RegisterGRPC == nil {
			return fmt.Errorf("server: service %s has nil RegisterGRPC", r.Descriptor.FullName())
		}
		if !cfg.DisableHTTP && r.RegisterHTTP == nil && httpServices[string(r.Descriptor.FullName())] {
			return fmt.Errorf("server: service %s declares HTTP routes but has nil RegisterHTTP", r.Descriptor.FullName())
		}
	}
	return nil
}

func validateRegisteredPolicies(cfg Config, set *policy.Set, surf *surface.Surface, extra []policy.Operation) error {
	if cfg.AllowUnregisteredPolicies {
		return nil
	}
	registered := make(map[string]struct{})
	for _, op := range surf.Operations() {
		registered[op.Operation.ID] = struct{}{}
	}
	for _, op := range extra {
		registered[op.ID] = struct{}{}
	}
	var missing []string
	for _, op := range set.Operations() {
		if _, ok := registered[op.ID]; !ok {
			missing = append(missing, op.ID)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("server: policy operations without registration: %s", strings.Join(missing, ", "))
	}
	return nil
}

func validateExtraConflicts(cfg Config, surf *surface.Surface, extra []policy.Operation) error {
	prefixByAPI := make(map[string]string, len(cfg.APIs))
	for _, a := range cfg.APIs {
		prefix := strings.TrimSpace(a.Prefix)
		if prefix == "" {
			continue
		}
		prefix = surface.NormalizePath(prefix)
		if prefix == "/" {
			prefix = ""
		}
		prefixByAPI[a.Name] = prefix
	}
	seen := make(map[string]string)
	for _, op := range surf.Operations() {
		for _, b := range op.HTTP {
			path := joinPaths(prefixByAPI[op.Operation.API], b.Path)
			seen[b.Verb+" "+path] = op.Operation.ID
		}
	}
	for _, op := range extra {
		key := op.ID
		if op.Metadata != nil && op.Metadata["method"] != "" {
			key = op.Metadata["method"] + " " + op.Metadata["path"]
		}
		if other, dup := seen[key]; dup {
			return fmt.Errorf("server: extra route %s conflicts with proto route %s", key, other)
		}
		seen[key] = op.ID
	}
	return nil
}

func validateCSRF(cfg Config) error {
	if cfg.CSRF != nil || cfg.AllowNoCSRF {
		return nil
	}
	for _, a := range cfg.Authenticators {
		if r, ok := a.(interface{ RequiresCSRF() bool }); ok && r.RequiresCSRF() {
			return fmt.Errorf("server: authenticator %T requires CSRF but Config.CSRF is nil", a)
		}
	}
	return nil
}

func validateAuthChain(cfg Config, chain *interceptor.Chain, set *policy.Set) error {
	hasProtected := false
	hasProtectedStream := false
	for _, op := range set.Operations() {
		if op.Policy.Anonymous {
			continue
		}
		hasProtected = true
		if op.Streaming {
			hasProtectedStream = true
		}
	}
	if !hasProtected {
		return nil
	}
	if !cfg.AllowNoAuthenticator && len(cfg.Authenticators) == 0 {
		return fmt.Errorf("server: protected policies exist but no Authenticators configured")
	}
	if !cfg.AllowNoAuthz && !chain.Has(interceptor.StageAuthz) {
		return fmt.Errorf("server: protected policies exist but interceptor chain has no authz stage")
	}
	if hasProtectedStream && !cfg.AllowNoAuthz && !chain.HasStream(interceptor.StageAuthz) {
		return fmt.Errorf("server: protected streaming methods exist but authz stage has no stream interceptor")
	}
	// 顺序校验：authz 必须位于 authn 之后，否则每个请求都在无 principal
	// 的状态下判定（GENERALIZATION §5.16：自定义链顺序合法、authn/authz
	// 位置正确）。Stage 按升序执行，比较在 Stages() 里的位置即可。
	if !cfg.AllowNoAuthz {
		authnIdx, authzIdx := -1, -1
		for i, st := range chain.Stages() {
			switch st.Name {
			case interceptor.StageAuthn:
				if st.Unary != nil {
					authnIdx = i
				}
			case interceptor.StageAuthz:
				if st.Unary != nil {
					authzIdx = i
				}
			}
		}
		if authnIdx >= 0 && authzIdx >= 0 && authzIdx < authnIdx {
			return fmt.Errorf("server: interceptor chain has authz stage before authn stage; authn must precede authz")
		}
	}
	// 受保护流式方法存在时，authn stage 也必须提供 stream 实现；缺失会让
	// 流式请求跳过认证，在 authz 处以 401 失败——fail-closed 但难以排查。
	if hasProtectedStream && !cfg.AllowNoAuthenticator && chain.Has(interceptor.StageAuthn) && !chain.HasStream(interceptor.StageAuthn) {
		return fmt.Errorf("server: protected streaming methods exist but authn stage has no stream interceptor")
	}
	return nil
}

func builtinRoutes(cfg Config) []ExtraRoute {
	var out []ExtraRoute
	if cfg.DisableHTTP {
		return nil
	}
	if !cfg.DisableHealth {
		out = append(out, GET("/healthz", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok\n"))
		})).Public())
		out = append(out, GET("/readyz", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.Readiness != nil {
				if err := cfg.Readiness(r.Context()); err != nil {
					http.Error(w, "not ready", http.StatusServiceUnavailable)
					return
				}
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ready\n"))
		})).Public())
	}
	return out
}

func safeHandle(mux *http.ServeMux, pattern string, h http.Handler) (err error) {
	defer func() {
		if v := recover(); v != nil {
			err = fmt.Errorf("server: register %q: %v", pattern, v)
		}
	}()
	mux.Handle(pattern, h)
	return nil
}

// withBodyLimit 用 http.MaxBytesReader 限制请求体大小；超限在读入时
// 报错（net/http 对未写响应的处理器补发 413）。
func withBodyLimit(next http.Handler, n int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, n)
		}
		next.ServeHTTP(w, r)
	})
}

func accessLog(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		logger.Info("http request", "method", r.Method, "path", r.URL.Path, "status", sw.status, "duration", time.Since(start))
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func joinPaths(parts ...string) string {
	var b strings.Builder
	for _, p := range parts {
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		b.WriteString(strings.TrimRight(p, "/"))
	}
	return surface.NormalizePath(b.String())
}

func (s *Server) Routes() []surface.RouteInfo {
	out := make([]surface.RouteInfo, len(s.routes))
	copy(out, s.routes)
	return out
}

// GRPCServer 返回装配完成的对外 gRPC server（服务注册、拦截器链、health、
// 反射）。供 lynx 等自有 runner 驱动生命周期：调用方自管 listener 与
// Serve/GracefulStop；Server.Shutdown 会 GracefulStop 同一实例，两者可混用。
// DisableGRPC 时返回 nil。
//
// 与 Run 的分工：Run 全托管（自带 listener/等待/关停）；GRPCServer + 自管
// Serve 保住 server.New 的装配与启动断言，把传输层生命周期留给宿主框架
// （lynxgrpc 自建 grpc.Server，不收预构建实例，因此以裸 server 形态交接）。
func (s *Server) GRPCServer() *grpc.Server {
	return s.externalServer
}

// HTTPHandler 返回装配完成的 HTTP handler（gateway + extra routes + 全局
// 中间件 + body limit），供 lynxhttp 等自有 HTTP runner 挂载：
//
//	srv, _ := server.New(ctx, cfg)
//	http := lynxhttp.NewServer(srv.HTTPHandler(), lynxhttp.WithAddr(":8080"))
//
// 首次调用启动 in-process 内部 gRPC（bufconn）并置 health SERVING；此后
// Run 不会重复启动。传输层超时（ReadHeaderTimeout 等）在该模式下由调用方
// 的 http.Server 决定，Config 中对应字段不生效。DisableHTTP 时返回 nil。
func (s *Server) HTTPHandler() http.Handler {
	if s.cfg.DisableHTTP {
		return nil
	}
	s.startInternal()
	return s.handler
}

// startInternal 启动 in-process 内部 gRPC（非 NetworkDial 且未禁用 HTTP 时）
// 并置 health SERVING；幂等（Run/HTTPHandler 共用，防双启动）。
func (s *Server) startInternal() {
	s.serveOnce.Do(func() {
		if !s.cfg.NetworkDial && s.bufLis != nil && s.internalServer != nil {
			go func() {
				if err := s.internalServer.Serve(s.bufLis); err != nil {
					s.logger.Warn("server: internal bufconn serve stopped", "error", err)
				}
			}()
		}
		if s.health != nil {
			s.health.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
		}
	})
}

func (s *Server) Operations() []policy.Operation {
	out := make([]policy.Operation, len(s.ops))
	copy(out, s.ops)
	return out
}

func (s *Server) Addrs() (grpcAddr, httpAddr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.grpcAddr, s.httpAddr
}

func (s *Server) Run(ctx context.Context) error {
	if s == nil {
		return fmt.Errorf("server: nil Server")
	}
	errCh := make(chan error, 4)
	var httpLis net.Listener
	var grpcLis net.Listener

	if !s.cfg.DisableGRPC {
		addr := s.cfg.GRPCAddr
		if addr == "" {
			addr = "127.0.0.1:9060"
		}
		lis, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		grpcLis = lis
		s.mu.Lock()
		s.grpcAddr = lis.Addr().String()
		s.mu.Unlock()
		go func() {
			if err := s.externalServer.Serve(lis); err != nil {
				errCh <- err
			}
		}()
	}
	if !s.cfg.DisableHTTP {
		s.startInternal()
		addr := s.cfg.HTTPAddr
		if addr == "" {
			addr = "127.0.0.1:8080"
		}
		lis, err := net.Listen("tcp", addr)
		if err != nil {
			_ = s.Shutdown(context.Background())
			return err
		}
		if s.cfg.TLS != nil {
			lis = tls.NewListener(lis, s.cfg.TLS)
		}
		httpLis = lis
		s.mu.Lock()
		s.httpAddr = lis.Addr().String()
		s.mu.Unlock()
		go func() {
			if err := s.httpServer.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
		}()
	}
	if s.health != nil {
		s.health.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	}
	s.logger.Info("server started", "grpc", grpcLisAddr(grpcLis), "http", listenerAddr(httpLis))
	select {
	case <-ctx.Done():
		shutdownCtx := context.Background()
		if s.cfg.ShutdownTimeout > 0 {
			var cancel context.CancelFunc
			shutdownCtx, cancel = context.WithTimeout(shutdownCtx, s.cfg.ShutdownTimeout)
			defer cancel()
		}
		return s.Shutdown(shutdownCtx)
	case err := <-errCh:
		_ = s.Shutdown(context.Background())
		return err
	}
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if s.health != nil {
		s.health.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
	}
	var errs []error
	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("server: http shutdown: %w", err))
		}
	}
	servers := []*grpc.Server{s.externalServer, s.internalServer}
	seen := make(map[*grpc.Server]struct{}, len(servers))
	for _, srv := range servers {
		if srv == nil {
			continue
		}
		if _, dup := seen[srv]; dup {
			continue
		}
		seen[srv] = struct{}{}
		done := make(chan struct{})
		go func(srv *grpc.Server) {
			srv.GracefulStop()
			close(done)
		}(srv)
		select {
		case <-done:
		case <-ctx.Done():
			srv.Stop()
			errs = append(errs, ctx.Err())
		}
	}
	if s.conn != nil {
		if err := s.conn.Close(); err != nil {
			errs = append(errs, fmt.Errorf("server: close gateway conn: %w", err))
		}
	}
	return errors.Join(errs...)
}

func grpcLisAddr(lis net.Listener) string {
	if lis == nil {
		return ""
	}
	return lis.Addr().String()
}

func listenerAddr(lis net.Listener) string {
	if lis == nil {
		return ""
	}
	return lis.Addr().String()
}
