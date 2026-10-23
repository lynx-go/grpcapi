# Changelog

本库处于 0.x：**minor 版本可携带破坏性变更**，升级前先读本文件与
[README](./README.md)「版本」章节。格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [SemVer](https://semver.org/lang/zh-CN/)。

## [Unreleased]（将发布为 v0.3.0）

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

### 发版前必做（打 v0.3.0 tag 前检查）

1. `genproto/` 当前相对 `genproto/v0.2.0` 已有漂移：先提交 proto 变更、
   打 `genproto/v0.3.0` tag、抬主仓 require，再打主仓 tag（release
   workflow 已机器校验内容一致性）。
2. torchwood 迁移验收（[MIGRATION.md](./MIGRATION.md) §6）。

## [v0.2.1] — 2026-10-21

- 策略集校验、inheritance、internal server 传输加固（`45256df`）。

## [v0.2.0] — 2026-10-21

- v3 落地：`policy` IR + 新 `authz` 替换旧包，gateway/guard v3 化；
  TLS、框架策略、继承与 guard 缺口收尾。

## [v0.1.0] — 2026-09-23

- 首个 tag。**不可用**：go.mod 对 `genproto` 的 require 是未发布的
  零值伪版本，外部解析必失败——请从 v0.2.0 起用。

[Unreleased]: https://github.com/lynx-go/grpcapi/compare/v0.2.1...HEAD
[v0.2.1]: https://github.com/lynx-go/grpcapi/compare/v0.2.0...v0.2.1
[v0.2.0]: https://github.com/lynx-go/grpcapi/compare/v0.1.0...v0.2.0
[v0.1.0]: https://github.com/lynx-go/grpcapi/releases/tag/v0.1.0
