# grpcapi

把「proto 声明 API + grpc-gateway 暴露」模式固化为可复用库：authz 策略注解收集 +
启动 fail-closed 断言、标准拦截器链、gateway 装配件、守卫测试 helper。构建于
[lynx](https://github.com/lynx-go/lynx) 生态之上。

设计文档见 [DESIGN.md](./DESIGN.md)。

## 最小接入清单（≤ 6 步）

1. `buf.yaml` deps 加 `buf.build/<org>/grpcapi`，proto 里 import 并注解：
   ```protobuf
   import "grpcapi/v1/authz.proto";
   service EchoService {
     option (grpcapi.v1.service_auth) = { default_access: ACCESS_LEVEL_END_USER };
     rpc Shout(ShoutRequest) returns (ShoutResponse) {
       option (google.api.http) = { post: "/v1/echo:shout", body: "*" };
       option (grpcapi.v1.method_auth) = { access: ACCESS_LEVEL_SERVER
                                           api_key_scope: { resource: "echoes" op: SCOPE_OP_WRITE } };
     }
   }
   ```
2. `go.mod` 加 `github.com/lynx-go/grpcapi`（传递引入扩展生成代码）。
3. 注册词表并收集策略：`grpcapi.authz.Build(files, authz.Options{Vocabulary: ...})`。
4. 装配：`interceptor.Assemble` 组拦截器链，`gateway.NewMux` + `gateway.Dial` +
   `gateway.Register` 组 HTTP 面（服务注册用生成的 `RegisterXxxHandlerClient` +
   `NewXxxClient` 包成 `gateway.RegisterFunc`，见 example/main.go）。
5. 启动断言：`interceptor.AssertAllRegisteredHavePolicy(srv, set)`。
6. 挂一条守卫：`guard.SwaggerAccessMatches(t, ...)`。

可运行参考：[example/](./example/)。

## 版本

0.x：minor 可携带破坏性变更，见各 tag 的 migration note。升级前请同步项目
`buf.lock` 与 `go.mod`（同 PR）。

## BSR 发布前的 vendored 过渡

库尚未发布 BSR 时，项目以 vendored 拷贝接入（torchwood 与 lynx-clean-template
两个先例的完整形态）：

1. 拷贝 `proto/grpcapi/v1/authz.proto` → 项目 `proto/third_party/grpcapi/v1/`
   （buf.yaml：主模块 `excludes: [proto/third_party]` + vendored 模块
   `lint/breaking use: []`；buf.gen.yaml：`inputs.exclude_paths` 文件级排除
   该文件——buf 不允许排除模块目录本身）。新 import 路径恰为
   `grpcapi/v1/authz.proto`，将来切 BSR deps 时 **import 零改动**。
2. `go.mod` 双 require（grpcapi + grpcapi/genproto）+ 双
   `replace ../grpcapi`（本地开发形态；**发布后** remove replace 改真实版本，
   git 构建环境如 Dokploy 不兼容本地路径）。
3. 漂移防线：vendored 同步守卫测试（双仓在位时字节级比对，单仓 CI 跳过）。

## 使用 guard.SwaggerAccessMatches 的前置

- 项目 buf.gen.yaml 的 openapiv2 插件需 `json_names_for_fields=false` 与
  `disable_default_errors=true`（分别被 snake_case 与 no-rpcStatus 守卫锁定）。
- proto 需带文件级 `openapiv2_swagger`（security_definitions + 顶层
  `x-access` 扩展 + responses.default 指向项目 ErrorResponse），形态参考
  torchwood `proto/client/v1/account.proto`。
- `ServiceAccess` 回调无需手写扩展解析：`func(s) (string, bool) {
  lv, ok := authz.ServiceDefaultAccess(s); return lv.String(), ok }`。
