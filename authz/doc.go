// Package authz 按 policy.Set 做授权决策，并提供 gRPC 拦截器与 HTTP
// 中间件两个执行入口；两者共享同一 Decider，保证双协议行为一致。
//
// # 决策模型
//
// Decider 是授权 SPI：默认 RequirementDecider 在 policy.Policy 树与
// registry 之上求值，项目可替换为 OPA/Cerbos 等外部引擎。求值语义：
//
//   - 同一 any_of 组内的多个 requirement 是 AND；组与组之间是 OR
//     （继承合并时 likewise，见 README「策略速查」）。
//   - forbid 恒为 deny-overrides：命中即拒绝，优先于任何 allow。
//   - 方法缺少策略 → fail-closed 拒绝（MissingPolicyCode，默认
//     Internal——缺策略是部署错误而非客户端越权），可放行的只有框架
//     内置服务（health、reflection 等，名单与 interceptor 侧同源）。
//   - stream 方法在建立时授权一次（open-time）；逐消息授权属于
//     项目自定义 Decider 的职责。
//
// # 错误约定
//
// 认证失败应表现为 Unauthenticated（由 authn 链产生）；authz 只对
// 「已认证但无权限」与「缺策略」给出 PermissionDenied。Decision.Code
// 可覆盖默认错误码；Reason 只进日志与审计，不下发客户端。
package authz
