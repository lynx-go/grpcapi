# grpcapi

[English](./README.md) | **简体中文**

grpcapi 把「proto 声明 API + grpc-gateway 暴露」模式固化为可复用库：策略收集 +
fail-closed 启动断言、认证/授权、标准拦截器链、gateway 装配件、守卫测试 helper。
属于 [lynx](https://github.com/lynx-go/lynx) 生态，但不依赖 lynx——直接依赖
只有 gRPC 生态（grpc、grpc-gateway、protobuf、jwt、protovalidate）。

## 特性

- **proto 是唯一事实源。** HTTP 路由来自 `google.api.http`，访问策略来自同一
  proto 文件上的 `grpcapi.v1` 注解，不需要在 Go 里维护第二份路由表。
- **启动 fail-closed。** 缺策略、operation 未注册、protected 路由没有认证器、
  缺 CSRF、路由冲突——全部在启动期报错，而不是请求期。
- **默认安全。** session cookie 默认 `Secure`；CSRF 未配置 `AllowedOrigins`
  时退化为仅同源；HTTP 请求体上限与 gRPC 收包上限同源。
- **一步装配。** `server.New` 自动完成 in-process gateway 连接、默认拦截器链、
  健康检查、路由表、启动断言与优雅退出。
- **守卫测试。** 对齐 proto 接口面、生成的 OpenAPI 文档与策略集；权限矩阵
  快照锁让每次授权面变更在 code review 中可见。

## 核心概念

| 概念 | 含义 |
|---|---|
| **Service** | 一个 gRPC service，以及它由 proto 自动生成的 HTTP 路由 |
| **Route** | 一个 HTTP 端点；通常来自 proto，少量 health/webhook 手写补充 |
| **Policy** | 谁可以调用：public / authenticated / role / permission / scope / 自定义 |
| **Principal** | 谁在调用：认证器产出的身份与 claims |

## 安装

```
go get github.com/lynx-go/grpcapi
```

需要 Go 1.26 及以上。proto 注解以独立 Buf 模块发布，见 [proto 分发](#proto-分发)。

## 快速上手

### 1. proto 声明路由与策略

```protobuf
import "google/api/annotations.proto";
import "grpcapi/v1/policy.proto";

option (grpcapi.v1.api) = {
  api: "public"
  schema_version: 1
  default_exposure: EXPOSURE_PUBLIC
};

service NoteService {
  option (grpcapi.v1.service) = {
    default_policy: { authenticated: true }
    default_exposure: EXPOSURE_PUBLIC
  };

  rpc ListNotes(ListNotesRequest) returns (ListNotesResponse) {
    option (google.api.http) = { get: "/v1/notes" };
  }

  rpc DeleteNote(DeleteNoteRequest) returns (DeleteNoteResponse) {
    option (google.api.http) = { delete: "/v1/notes/{id}" };
    option (grpcapi.v1.method) = {
      policy: { permissions: ["notes.read", "notes.delete"] }
      label: "permission"
    };
  }

  rpc PurgeNotes(PurgeNotesRequest) returns (PurgeNotesResponse) {
    option (google.api.http) = { post: "/v1/notes:purge" body: "*" };
    option (grpcapi.v1.method) = {
      policy: {
        any_of: [
          { roles: ["admin"] },
          { scopes: ["notes:admin"] }
        ]
      }
      label: "server"
    };
  }
}
```

路由唯一事实源是 proto Service + `google.api.http`；不要在 Go 里维护第二份路由表。

### 2. 构建策略集

```go
import (
    "github.com/lynx-go/grpcapi/policy"
    "github.com/lynx-go/grpcapi/policy/protopolicy"
)

set, err := policy.Build(ctx,
    policy.FromRegistry("notes.api.v1"), // 或 policy.FromFiles / FromFileDescriptorSet
    policy.Options{
        Provider: protopolicy.New(protopolicy.Options{}),
        Registry: policy.DefaultRegistry(),
        // Vocabulary: policy.NewVocabulary(map[string][]string{"scope": {"notes"}}),
    })
```

### 3. 一步装配（推荐）

```go
srv, err := server.New(ctx, server.Config{
    Policy: set,
    Services: []server.Registration{{
        API:        "public",
        Descriptor: notesv1.File_notes_proto.Services().ByName("NoteService"),
        RegisterGRPC: func(s *grpc.Server) {
            notesv1.RegisterNoteServiceServer(s, impl)
        },
        RegisterHTTP: func(ctx context.Context, mux *runtime.ServeMux, conn grpc.ClientConnInterface) error {
            return notesv1.RegisterNoteServiceHandlerClient(ctx, mux, notesv1.NewNoteServiceClient(conn))
        },
    }},
    GRPCAddr: ":9060",
    HTTPAddr: ":8080",
    // 本例未配置 Authenticators，而第 1 步的 proto 声明了 protected 策略；
    // fail-closed 语义要求显式承认这一点，否则 server.New 启动报错。
    // 生产接入 JWT/session/API key 后删除此开关。
    AllowNoAuthenticator: true,
})
if err != nil {
    log.Fatal(err)
}
log.Fatal(srv.Run(ctx))
```

`server.New` 自动完成：in-process gateway 连接、mux/dial/register/mount、默认
interceptor 链、健康检查、路由表、启动断言与优雅退出。

Registration 闭包可以不手写，用随库附带的 protoc 插件生成：

```bash
go build -o bin/protoc-gen-grpcapi ./cmd/protoc-gen-grpcapi
```

```yaml
# buf.gen.yaml
plugins:
  - local: bin/protoc-gen-grpcapi
    out: .
    opt: module=github.com/lynx-go/grpcapi
```

生成 `NewNoteServiceRegistration(impl) server.Registration`。
Tier 1 仍可逐件组装 `gateway.NewMux` / `gateway.Dial` / `gateway.Register`。

### 4. 逐件装配

```go
decider, err := authz.NewRequirementDecider(set)
authorizer, err := authz.NewInterceptor(set, decider, authz.InterceptorOptions{})

chain, err := interceptor.Assemble(
    interceptor.RecoveryStage(interceptor.RecoveryOptions{}),
    interceptor.RequestIDStage(interceptor.RequestIDOptions{}),
    interceptor.ClientInfoStage(interceptor.NewClientInfo(interceptor.ClientInfoConfig{})),
    interceptor.AuthnStage(authnUnary, authnStream),
    interceptor.AuthzStage(authorizer.Unary(), authorizer.Stream()),
    interceptor.ValidateStage(interceptor.NewValidate()),
)
srv := grpc.NewServer(chain.ServerOptions()...)
```

`authn` 参考实现：`authn/jwt`、`authn/session`、`authn/apikey`、`authn/admin`，
CSRF 中间件在 `csrf`。

逐件装配时需在启动期手动断言「每个已注册方法都有策略」（`server.New` 已内置）：

```go
if err := interceptor.AssertAllRegisteredHavePolicy(srv, set); err != nil {
    log.Fatal(err)
}
```

## 守卫测试

```go
surf, err := surface.Build([]protoreflect.FileDescriptor{notesv1.File_notes_proto}, set)
if err != nil {
    t.Fatal(err)
}
docs, err := guard.OpenAPIv2(os.DirFS("gen"), guard.OpenAPIv2Options{})
if err != nil {
    t.Fatal(err)
}

guard.Run(t, guard.SuiteConfig{
    Surface: surf,
    Docs:    docs,
    Policy: guard.MatchOptions{
        MetadataKey:   "x-grpcapi-policy",
        MinOperations: 3,
    },
    Naming:   guard.SnakeCase,
    Manifest: &guard.ManifestConfig{Path: "docs/policy.manifest.json"},
    Matrix: &guard.MatrixConfig{
        Path: "docs/authz-matrix.md",
        Options: guard.MatrixOptions{
            Header: []string{"Method", "Label"},
            Row: func(op policy.Operation) []string {
                return []string{op.ID, op.EffectiveLabel()}
            },
        },
    },
})

// 启动装配结果守卫：比对路由表与策略集。
guard.AssertRouteTable(t, srv.Routes(), guard.RouteTableOptions{Policies: set})
```

旧 `SwaggerAccessMatches` / `SwaggerSnakeCaseProperties` / `SwaggerNoDefinition`
仍保留；新项目建议用 `guard.Run(SuiteConfig{...})` 组合 `Document` 断言。

## 策略速查

```protobuf
policy: { anonymous: true }                 // 公开
policy: { authenticated: true }             // 登录即可
policy: { roles: ["admin"] }                // 任一角色
policy: { permissions: ["notes.read"] }     // 全部权限
policy: { scopes: ["notes:write"] }         // 任一 scope
policy: { any_of: [ { roles: ["admin"] }, { scopes: ["notes:admin"] } ] }
policy: { preset: "tw.server" preset_args: { scope: "echoes:write" } }
policy: { require: [ { kind: "tenant" values: ["acme"] } ] }
```

- 默认 registry：`authenticated` / `claim` / `principal_kind` / `role` / `permission` / `scope`。
- default scope 是精确 claim 匹配；`resource:op` 语义用 `policy/scope` 注册
  （兼容 v2 的 `resource.op`）。
- `forbid` 是 deny-overrides。
- `inherit_default: true` 时方法策略与 service/file 默认合并：
  `require`/`forbid` 跨层 AND（forbid 恒 deny-overrides）；`any_of` 的各组
  直接并入备选列表——组间恒为 OR，继承不做跨层笛卡尔 AND。要在默认之上
  做交集，把多组条件写进同一个 `any_of` 组（组内 AND）。

## 包一览

| 包 | 职责 |
|---|---|
| [`policy`](./policy) | 策略收集与求值；[`policy/protopolicy`](./policy/protopolicy) 读取 proto 注解 |
| [`authz`](./authz) | 授权决策；gRPC 拦截器与 HTTP 中间件共享同一 Decider |
| [`authn`](./authn) | 认证器接口与参考实现：`jwt` / `session` / `apikey` / `admin` |
| [`interceptor`](./interceptor) | 标准拦截器链：recovery、request ID、client info、authn/authz 挂点、校验 |
| [`gateway`](./gateway) | grpc-gateway 装配件：mux、dial、register、HeaderPolicy、错误编码 |
| [`server`](./server) | 组合根：一步装配，内置启动断言 |
| [`guard`](./guard) | 测试期断言：对齐 proto 接口面、OpenAPI 文档与策略 |
| [`surface`](./surface) | 由 proto + policy 派生的统一 API 接口面 IR |
| [`csrf`](./csrf) | double-submit cookie 形式的 CSRF 中间件 |
| [`principal`](./principal) | 请求身份主体与 claims，含 context 存取 |
| [`contextx`](./contextx) | context 上的 request ID / client info / audit 辅助 |
| [`testkit`](./testkit) | `server.New` 的测试夹具；仅测试代码使用 |

## proto 分发

proto 模块发布 BSR：`buf.build/lynx-go/grpcapi`。项目 `buf.yaml` 登记 deps：

```yaml
version: v2
deps:
  - buf.build/lynx-go/grpcapi
```

proto 里 `import "grpcapi/v1/policy.proto"`。v3 已删除 `authz.proto`：旧注解
按 [MIGRATION.md](./MIGRATION.md) 路径 A vendored 到项目侧，经 legacy
Provider 消费，不面向新项目。

## 文档

- [example/](./example) —— 可运行的 Tier 0 示例：proto 声明路由与策略，
  `server.New` 完成其余装配。
- [MIGRATION.md](./MIGRATION.md) —— 从 v2 升级，含旧 `authz` 注解的去向。
- [GENERALIZATION.md](./GENERALIZATION.md) —— 完整设计与决策。设计稿性质，
  API 以 godoc 为准。
- [docs/history/DESIGN.md](./docs/history/DESIGN.md) —— v2 设计留档。
- [CHANGELOG.md](./CHANGELOG.md) —— 变更摘要。

## 版本

- 0.x：minor 可携带破坏性变更，升级前先读 [CHANGELOG.md](./CHANGELOG.md)
  与迁移指南。
- **最低可用版本 v0.2.0**：v0.1.0 的 go.mod 对 `genproto` 的 require 是
  未发布的零值伪版本，外部解析必失败，请勿引用。
- `genproto` 是独立 Go module，主仓的 `replace` 只对本仓生效：升级时必须
  **先**给 genproto 打 tag，**再**抬主仓 require 版本——漏发 tag 会让下游
  在 resolve 失败处得到隐晦的编译错误。

## 许可

[Apache-2.0](./LICENSE)
