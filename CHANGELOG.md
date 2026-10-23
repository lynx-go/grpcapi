# Changelog

本库处于 0.x：**minor 版本可携带破坏性变更**，升级前先读本文件与
[README](./README.md)「版本」章节。格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [SemVer](https://semver.org/lang/zh-CN/)。

## [v0.3.0] — 2026-10-23

### 执行侧迁移补课（torchwood §11.4 迁移实测反馈）

- **resource 实例门方向感知（G-1 修复）**：Requirement 声明值扩展
  `<resource>:<op>` 形态（如 `databases:read`）；新增
  `scope.GrantsInstanceFor(set, resource, target, op, allowWildcard)`——
  带方向后缀的实例 token（`databases:blog.read`）仅在实例命中且方向一致
  时授予，无后缀实例 token 视为全方向。`GrantsInstance` 行为不变（op 为空
  不剥实例段后缀，兼容不变量）。声明值携带非 op 后缀（`databases:blog`）
  仍构建失败——实例寻址属 principal 授权面。torchwood T-02「单 token =
  方向 + 实例」合取语义由此可全量表达（组间 OR 组合范式见
  `authz/composite_gate_test.go`）。
- **Stream open-time 授权文档化（G-2）**：open-time 求值不携带请求消息，
  依赖请求寻址的谓词（resource 实例门）恒无目标——此类方法应使用
  StreamAuthPerMessage 或要求资源整体/通配授权（拦截器文档已注明）。

### 面向真实消费者的补课（torchwood/fleetly 双项目审核结论）

- **CORS**：新增 `cors` 包（`server.Config.CORS` 全局挂载或
  `APIConfig.Middleware` 按面挂载）。安全默认：未配置 origin 列表 = 不放行
  任何跨源；origin 只做精确匹配不做反射；`"*"` 与 credentials 互斥；预检
  请求头逐个比对（fail-closed）。此前浏览器安全面只有 CSRF 一半。
- **HTTP body limit 解耦 + 逐路由豁免**：`Config.HTTPBodyLimitBytes` 显式
  分离 HTTP 请求体上限与 gRPC `MaxRecvMsgSize`（默认仍同源）；新增
  `ExtraRoute.MaxBodyBytes` 逐路由放宽（文件上传场景），豁免不放大 proto
  路由与 gRPC 消息上限。
- **RateLimit / Audit / Usage 参考实现**：新增 `ratelimit`（固定窗口内存
  限流，ResourceExhausted + RetryInfo）、`audit`（slog/Sink 落审计，
  best-effort 契约 + Include 噪声治理）、`usage`（内存计量 + Snapshot）
  三个包，各自提供 `Stage()` 直接填 `interceptor` 槽位。能力矩阵不再只有
  空槽位。
- **gateway facade API 冻结（范围扩展）**：v0.3.0 起**消费者已采用的全部
  核心面**冻结至 v1——`gateway` 全部公开符号、`interceptor.Stage` 及其
  name/order 常量、`policy.Build`/`policy.Set`、`authn.Options`/`authn.Chain`。
  破坏性变更只允许新类型/新函数/新字段（additive-only），不再移动、重命名
  或删除既有符号。v0.2.1 删除的 `IncomingMatcher` /
  `OutgoingMatcher` / `NewErrorHandler` / `ErrorBodyBuilder` 以 Deprecated
  垫片恢复（`gateway/compat.go`，内部委托新实现，v1.0 移除），torchwood
  升级路径重新可编译。
- **自有 runner 集成（lynx 双轨消除）**：`Server.GRPCServer()` 返回装配完成
  的 gRPC server、`Server.HTTPHandler()` 返回完整 HTTP handler（首调幂等启动
  in-process 内部 gRPC，与 Run 不冲突）——宿主框架（lynx 等）驱动传输层
  生命周期时仍可获得 server.New 的装配与启动断言，不再被迫停在 Tier 1。
- **执行侧迁移定为 v1.0 硬验收**（GENERALIZATION §11.4 / MIGRATION §6）：
  torchwood legacy 双投影退役、授权执行走库 Decider 之前，v1.0 不打 tag。
- **query 票据凭证**：`authn.WithQueryTicket`（HTTP 面显式组合，默认不
  从 query 取凭证）+ `x-ticket` metadata（gRPC 面）+ `authn/ticket`
  认证器参考实现（Store 兑换语义，单用途/TTL 由实现保证）。覆盖
  EventSource/浏览器 WebSocket 无法带 header 的场景。
- **无效凭证策略按凭证族细分**：`authn.Options.InvalidCredentialByKind`
  在方法粒度之上叠加凭证族粒度（public 面无效 Bearer/cookie 降级匿名、
  无效 API key 恒 401 防暴测）；多凭证在场时 fail-closed 合并。
- **资源实例寻址 scope**：`policy/scope.ResourceKind`（torchwood
  `databases:blog` 形态的官方范式）：Requirement 声明寻址的资源，运行期
  经 `FieldID/QueryID/PathID` 从请求提取目标实例，与 principal scope 集合
  比对；操作级 token（read/write/admin）不授予实例寻址。
- **流式 HTTP 桥参考实现**：新增 `bridge` 包——SSE（事件帧/心跳/retry/
  错误事件脱敏）、HTTP body → client-streaming 分帧上传（413/body limit
  语义衔接、gRPC status 统一错误体）、WebSocket JSON 信封（coder/websocket，
  每消息凭证复验 Reauth、心跳、错误信封脱敏）。采用方不再自写 ~400 行
  协议桥。
- **`guard.InjectLabels` 落地**（GENERALIZATION §8.6 方案 3）：把 Surface
  派生 label 注入 OpenAPI 文档的 `x-grpcapi-policy` 扩展，未命中文件透传；
  与 `guard.OpenAPIv2` 同一套匹配规则，文档对账闭环补全。
- **复合门执行侧闭环证明**：`authz/composite_gate_test.go` 用库内 kind
  （claim/scope/resource）完整表达 torchwood SERVER 档（admin 角色 ∪
  api-key scope×实例门组内 AND）并由库 Decider 执行——策略声明与执行
  均在库内，legacy 双投影的终点形态已验证。

### 破坏性变更（Breaking）

- **gateway**：v2/v3 双轨收敛为单轨 `HeaderPolicy`/`ErrorEncoder`
  （`78504c4`）。删除旧 `ErrorHandler`、`IncomingExtra`、`OutgoingDirect`、
  `IncomingMatcher`、`OutgoingMatcher`、`NewErrorHandler`、
  `ErrorBodyBuilder`；迁移映射见 [MIGRATION.md](./MIGRATION.md)。
- **any_of 继承合并语义钉死**（`dcb5d7b`）：方法策略与 service/file 默认
  合并时，`any_of` 各组直接并入备选列表——**组间恒为 OR**，不做跨层
  笛卡尔 AND；要交集就把多组条件写进同一个组（组内 AND）。
- **secure-by-default**（`fab9bca`）：session cookie 默认 `Secure`（本地
  明文需显式 `InsecureCookie`）；CSRF 空 `AllowedOrigins` 语义从「跳过」
  改为「仅同源」；HTTP 请求体上限默认与 `MaxRecvMsgSize` 同源（8MiB）。

### 安全

- client-ip / admin_roles / JWT 信任链加固（`dcb5d7b`）：trusted proxies
  空 = 不信任任何转发头；admin store 故障 fail-closed；JWT 默认强制
  `exp`、算法白名单排除 `none`/HS。
- JWKS 单飞刷新 + Ed25519 支持（`af6658f`、`0312336`）。
- validate 错误脱敏，错误映射统一（`af6658f`）。

### 新增

- `interceptor`：预留 `RateLimitStage` / `AuditStage` / `UsageStage` 槽位；
  `MustFrom` 系列改为真 panic 约定（`3078ef6`）。
- `guard`：`guard.Run(SuiteConfig)` 组合断言、codegen golden 测试。
- CI：govulncheck + gosec + golangci-lint + race + 覆盖率门槛 65%
  （实测 ~70%）；`buf.lock` pin；release 工作流含 genproto tag 同步与
  **内容一致性**校验。
- codegen 生成头带版本戳（干净 tag 构建显示真实版本，其余为 `dev`）；
  升级库后需重新 `buf generate`。

### 文档与发布

- 新增 **LICENSE**（Apache-2.0）——本仓库自此才有对外分发授权。
- README §4 `server.New` 示例补 `AllowNoAuthenticator: true`（原示例
  照抄会因 fail-closed 启动失败）。
- `server` / `guard` / `authz` / `interceptor` 补 package doc（doc.go）。
- GENERALIZATION.md 标注为设计稿（API 以 godoc 为准）并回写 15 处
  API 漂移；v2 设计留档移至 `docs/history/DESIGN.md`。
- MIGRATION.md 新增「迁移完成后的一次性整形清单」。
- 生成物版本戳 + `example/echo` 生成文件随插件更新。

### 发版前必做（已于 2026-10-23 完成）

1. `genproto/v0.3.0` tag 已打、主仓 require 已抬（release workflow 机器
   校验内容一致性）。
2. torchwood 迁移验收通过（[MIGRATION.md](./MIGRATION.md) §6 十项全绿；
   G-1/G-2 补课见上文，torchwood 侧证据 `docs/developer/21-grpcapi-execution-migration.md`）。

## [v0.2.1] — 2026-10-21

- 策略集校验、inheritance、internal server 传输加固（`45256df`）。

## [v0.2.0] — 2026-10-21

- v3 落地：`policy` IR + 新 `authz` 替换旧包，gateway/guard v3 化；
  TLS、框架策略、继承与 guard 缺口收尾。

## [v0.1.0] — 2026-09-23

- 首个 tag。**不可用**：go.mod 对 `genproto` 的 require 是未发布的
  零值伪版本，外部解析必失败——请从 v0.2.0 起用。

[Unreleased]: https://github.com/lynx-go/grpcapi/compare/v0.3.0...HEAD
[v0.3.0]: https://github.com/lynx-go/grpcapi/compare/v0.2.1...v0.3.0
[v0.2.1]: https://github.com/lynx-go/grpcapi/compare/v0.2.0...v0.2.1
[v0.2.0]: https://github.com/lynx-go/grpcapi/compare/v0.1.0...v0.2.0
[v0.1.0]: https://github.com/lynx-go/grpcapi/releases/tag/v0.1.0
