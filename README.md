# grpcapi

把「proto 声明 API + grpc-gateway 暴露」模式固化为可复用库：策略收集 +
fail-closed 启动断言、认证/授权、标准拦截器链、gateway 装配件、守卫测试 helper。
构建于 [lynx](https://github.com/lynx-go/lynx) 生态之上。

> **v3 迁移中**：当前 `main` 已删除旧 `authz` 包，改用 `policy` + 新 `authz`。
> 完整设计、决策与迁移计划见 [GENERALIZATION.md](./GENERALIZATION.md)，
> v2 → v3 落地步骤见 [MIGRATION.md](./MIGRATION.md)。v2 设计留档见
> [DESIGN.md](./DESIGN.md)。

## 核心概念

| 概念 | 含义 |
|---|---|
| **Service** | 一个 gRPC service，以及它由 proto 自动生成的 HTTP 路由 |
| **Route** | 一个 HTTP 端点；通常来自 proto，少量 health/webhook 手写补充 |
| **Policy** | 谁可以调用：public / authenticated / role / permission / scope / 自定义 |
| **Principal** | 谁在调用：认证器产出的身份与 claims |

## 最小接入（当前可用路径）

### 1. proto 声明

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

### 2. 构建策略

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

### 3. 认证 + 授权拦截器

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

### 4. 一步装配（推荐）

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
})
if err != nil {
    log.Fatal(err)
}
log.Fatal(srv.Run(ctx))
```

`server.New` 自动完成：in-process gateway 连接、mux/dial/register/mount、默认
interceptor 链、健康检查、路由表、启动断言与优雅退出。

可选 codegen（生成同样的 Registration，省掉手写闭包）：

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

### 5. 启动断言

```go
if err := interceptor.AssertAllRegisteredHavePolicy(srv, set); err != nil {
    log.Fatal(err)
}
```

`server.New` 已内置该断言；逐件组装时需要手动调用。

### 6. 守卫

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

// 启动装配结果守卫
guard.AssertRouteTable(t, srv.Routes(), guard.RouteTableOptions{Policies: set})
```

旧 `SwaggerAccessMatches` / `SwaggerSnakeCaseProperties` / `SwaggerNoDefinition` 仍保留；
新项目建议用 `Suite` + `Document`。

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
- `inherit_default: true` 表示方法策略与 service/file 默认按 AND 合并。

## proto 分发

proto 模块发布 BSR：`buf.build/lynx-go/grpcapi`。项目 `buf.yaml` 登记 deps：

```yaml
version: v2
deps:
  - buf.build/lynx-go/grpcapi
```

proto 里 `import "grpcapi/v1/policy.proto"`。旧 `authz.proto` 仅作为迁移期
legacy Provider 的输入保留，不面向新项目。

## 版本

0.x：minor 可携带破坏性变更。v3 已删除旧 `authz` API；升级前读
[GENERALIZATION.md](./GENERALIZATION.md) 的迁移章节。
