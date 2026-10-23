// Package interceptor 提供标准 gRPC 拦截器链：panic 恢复、request ID、
// 客户端信息、认证/授权挂点、消息校验，以及把 Stage 装配为
// grpc.ServerOption 的 Assemble。
//
// # Stage 与顺序
//
// 每个能力是一个 Stage{Name, Order, Unary, Stream}；内置顺序常量
// （OrderRecovery=0 … OrderValidate=80）约定执行顺序：recovery 最外层，
// validate 最内层。Assemble 校验 Stage 非空、名字唯一、Order 不回退，
// Chain.ServerOptions() 直接喂给 grpc.NewServer。AuthnStage 与
// AuthzStage 只提供挂点，实现分别来自 authn 认证器与 authz.Interceptor；
// RateLimit/Audit/Usage 是预留槽位，库不内置实现。
//
// # stream 约定
//
// stream 拦截器包装 ServerStream.Context()，使 handler 内拿到的 ctx
// 与 unary 一致（requestid/clientinfo/authn/authz 均如此）；包装器
// 转发 SendMsg/RecvMsg/SetHeader/SetTrailer。validate 对 client-streaming
// 与 bidi 逐条 RecvMsg 校验，server-streaming 只校验首个请求。
//
// # 启动断言
//
// AssertAllRegisteredHavePolicy 断言每个已注册 gRPC 方法都在策略集中
// （框架豁免除外），把「proto 注解与注册实现漂移」提前到启动期；
// server.New 已内置该断言，逐件组装时需手动调用。FrameworkExempt
// 是框架服务豁免名单（health/reflection 等）的唯一来源，validate
// 拦截器复用同一名单。
package interceptor
