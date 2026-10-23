// Package server 把 policy、surface、authn、authz、interceptor、gateway
// 组装成可运行的 gRPC + grpc-gateway 双协议服务，是本库的组合根。
//
// 典型用法是 New(ctx, Config{Policy, Services, GRPCAddr, HTTPAddr})：
// 进程内 bufconn 连接 gateway、默认拦截器链、健康检查与路由表都在
// 一步内完成；Tier 1 用户可绕过本包逐件组装（见 README §3）。
//
// # 启动断言（fail-closed）
//
// New 在返回前聚合校验配置，任一失败即返回 error，不产出半启动状态：
//
//   - Policy 与 PolicySource 二选一；每个 Registration 的 Descriptor 与
//     RegisterGRPC 非 nil，声明了 HTTP 路由的 service 必须有 RegisterHTTP。
//   - 策略集中的每个 operation 都有对应注册（共享策略集时用
//     AllowUnregisteredPolicies 放宽）；每个 gRPC 方法都有策略。
//   - 存在非 anonymous 策略但没有认证器 → 启动失败，除非显式设置
//     AllowNoAuthenticator（表示由网络层/网格兜底认证）。
//   - session 类认证器要求 CSRF（RequiresCSRF 为 true 而 Config.CSRF
//     为 nil）→ 启动失败，除非显式 AllowNoCSRF。
//   - authn Stage 必须先于 authz；proto 路由、extra 路由之间无
//     verb+path 冲突；多 API 面名称唯一且前缀不互相遮蔽。
//
// # TLS 与双 server 语义
//
// TLS 或 GRPCOptions 非空时，服务会同时创建 external（TLS/带选项）与
// internal（plaintext）两个 gRPC server：gateway 经 internal 侧拨号，
// 避免把传输凭证带进进程内回环。因此 Registration.RegisterGRPC 可能被
// 调用两次——回调必须复用同一个 service 实现，不要每次新建带状态对象。
//
// # 逃生口
//
// 默认值安全但克制：NetworkDial 切换网络回环、ExtraRoutes 挂原生 HTTP
// 路由（仅限 health/webhook 等，见 GENERALIZATION §5.19）、
// HTTPMiddleware 挂全局 net/http 中间件、Docs 挂 OpenAPI 文档端点。
package server
