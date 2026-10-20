# grpcapi 泛化设计 v3（完整版）

> 目标不是「做一个万能 API 框架」，而是做一个**分层可退让的 API 机制库**：
>
> - 小项目：少写代码，默认即安全。
> - 中型产品：按需组合包，保留全部控制权。
> - 平台型项目：能替换策略来源、决策引擎、认证方式、传输层和文档管线。
>
> 内部试用期，不做向后兼容；当前 v2.1 打 tag 保留。

---

## 0. 设计目标：方便、通用、可特化

### 0.1 三层 API

| 层 | 使用者 | 入口 | 目标 |
|---|---|---|---|
| Tier 0 约定层 | 小内部 API、原型 | `server.New` + proto 糖 + 默认 registry/chain/gateway | 20~30 行跑通 gRPC + HTTP |
| Tier 1 组合层 | 产品 API | 逐包使用 `policy` / `authn` / `authz` / `interceptor` / `gateway` / `guard` | 每个机制可替换、可观测 |
| Tier 2 特化层 | 平台、旧系统迁移 | 实现 `Provider` / `Preset` / `RequirementKind` / `Decider` / `Authenticator` / `ResourceResolver` / `Loader` | 库不感知项目领域模型 |

三层必须共用同一套机制。Tier 0 不是另一套实现，只是对 Tier 1 的组合封装；否则行为必然漂移。

### 0.2 三个能力轴

1. **方便**：proto 侧有糖，Go 侧有默认值和一行装配，测试侧有 `testkit` 和 `guard.Suite`。
2. **通用**：核心只依赖「描述符 + 不可变 IR + 谓词求值」，不依赖 torchwood 的凭证分类法，也不依赖 grpc-gateway。
3. **特化**：每一个可能因项目而异的点都有明确 SPI，且默认实现可替换；项目不需要 fork。

### 0.3 非目标

- 不做通用策略语言/DSL 解释器。
- 不在 core 实现 JWT/OIDC/session/API key 认证器。
- 不实现 OPA/Cerbos/Casbin/SpiceDB，只提供接入点。
- 不强制使用 grpc-gateway；v3 只提供 grpc-gateway 适配器，但核心不依赖它。
- 不做脚手架命令；example + README 是活文档。
- 不做配置文件 schema；配置是项目主权。

### 0.4 开发者体验原则

1. **一个显而易见的主路径**：常见需求只有一种写法，不要求开发者在多种等价方案里选择。
2. **零必需配置也能跑**：本地开发/测试只给 Policy + Services 就能启动；地址、日志、错误体、健康检查有安全默认。
3. **每个默认都可替换**：默认不是硬编码，Tier 1/2 用户随时接管。
4. **渐进披露**：Day 1 只需要理解四个概念；Provider/Preset/Kind/Decider 是第二周以后的事。
5. **错误可行动**：构建/启动/守卫错误必须指出「哪个方法/路由、哪条策略、怎么修」；聚合全部违例，不挤牙膏。
6. **无全局魔法**：没有 `init()` 注册表、没有隐藏单例；依赖显式传递。
7. **测试是一等公民**：`testkit` + `guard.Suite` 与运行时 API 同等重要。
8. **安全默认**：方便不能以 fail-open 为代价；public 必须显式，未知字段默认拒绝。
9. **路由装配是一等能力**：路由仍由 proto Service + `google.api.http` 定义；库负责把 gRPC + gateway 自动装配好，原生 HTTP 路由只作为少量逃生口。
10. **代码即文档**：不要求 codegen 才能跑通；生成器只消除样板，不承载隐藏语义。
11. **零值安全**：`Config{}` 的零值必须等于安全默认。布尔字段用
    `DisableX` / `SkipX` / `AllowX` 命名，避免「零值到底是开还是关」的歧义
    （例：`DisableHealth`、`SkipMetadata`、`AllowNoAuthenticator`）。

### 0.5 核心四概念与学习路径

Day 1 只需要四个概念：

| 概念 | 含义 |
|---|---|
| **Service** | 一个 gRPC service，以及它由 proto 自动生成的 HTTP 路由 |
| **Route** | 一个 HTTP 端点；通常来自 proto，少量 health/webhook/static 手写补充 |
| **Policy** | 谁可以调用：public / authenticated / role / permission / scope / 自定义 |
| **Principal** | 谁在调用：认证器产出的身份与 claims |

其余能力按需展开：

```text
Day 1     Service + Route + Policy + Principal + server.New
Week 1    testkit + guard.Suite + 自定义 Authenticator
Week 2    Preset + 自定义 RequirementKind + 路由分组/中间件
Month 1   Provider + Decider + ResourceResolver + 多 API
平台化    OPA/Cerbos/SpiceDB、Connect、自定义传输/文档管线
```

这条路径保证：**新手不被 SPI 淹没，老手不被默认值限制。**

---

## 1. 现状诊断：为什么现在「不方便也不通用」

| 位置 | 当前实现 | 问题 |
|---|---|---|
| `authz.AccessLevel` | PUBLIC/END_USER/SERVER/PERMISSION/SYSTEM | 把凭证族、角色、scope、permission 压成一个枚举，语义完全是 torchwood 的 |
| `MethodAuth` | `permissions` / `admin_roles` / `api_key_scope` 固定字段 | 新项目要加 tenant/audience/mTLS 只能改库 |
| `ScopeOp` | read/write/admin | 只适用于一种资源/方向 scope 语言（v2 用 `resource.op`） |
| `Vocabulary` | 只有 `ScopeResources` | 角色、权限、租户等词表无处注册 |
| `Build` | 手工传 `[]FileDescriptor` | 大项目易漏文件，启动断言空转 |
| 拦截器链 | 固定 Slot，ClientInfo 首、Validate 尾，仅 unary | 没有这些阶段的项目无法装配；不能插 recovery/metrics；不支持 stream |
| 认证 | 无 | 项目自己写，且与策略模型耦合 |
| 授权 | 只收集，不执行 | 项目自己写执行器，容易与收集语义漂移 |
| `gateway.ErrorBodyBuilder` | 必须返回 `proto.Message`；`SanitizeInternal` 恒 true | 错误体形状被 protojson 绑架 |
| `gateway` header matcher | 硬编码 authorization 拒绝 + torchwood 专属头 | 头策略是项目契约 |
| `gateway.Dial` | 同地址拨号、8MiB、默认 insecure | 只适合同机部署 |
| `guard.Swagger*` | genproto 目录、`*.swagger.json`、`operationId` 解析、`ErrorResponse` 命名 | 只适用于 openapiv2 + buf 文件布局 + torchwood 命名 |
| `guard.AssertMethodCount` | 全局 `protoregistry` + 包前缀 | 依赖全局注册，测试间互相污染 |
| `guard.AssertServiceCoverage` | 去 `Service` 后缀 + 首字母小写 | SDK 命名约定写死 |
| 发布 | 双 Go module + `replace` | 接入成本高，git 构建环境不兼容本地 replace |
| 示例 | 直接演示 torchwood 的 access 语义 | 新用户以为库只能这样用 |

还有一个隐蔽耦合：**策略来源被写死为 `grpcapi.v1` 扩展**。这导致旧系统迁移、外部策略源、运行时配置覆盖都无路可走。

核心判断：**当前不是「选项不够多」，而是「 torchwood 的领域模型进了库的核心类型」。** 泛化首先要删类型，而不是加开关。

---

## 2. 核心设计：五个抽象 + 一个 IR

### 2.1 一个 IR：`Surface`

所有消费者都从同一个描述符视图取数据：

```text
FileDescriptor
  ├─> policy.Set         方法有效策略、暴露面、标签、API 归属
  └─> surface.Surface    HTTP 绑定、输入/输出描述符、流式信息
         ├─> gRPC 注册与启动断言
         ├─> gateway 注册
         ├─> OpenAPI 守卫
         ├─> SDK 覆盖守卫
         └─> 授权矩阵/文档生成
```

`Surface` 是 **transport-agnostic** 的。它只描述「这个方法暴露成什么」，不描述「用 grpc-gateway 还是 Connect 实现」。

### 2.2 一个策略模型：`Policy`

```text
Policy = 显式 anonymous
       + 便捷糖（authenticated / roles / permissions / scopes）
       + 通用 require  (AND)
       + any_of        (OR of AND groups)
       + forbid        (deny-overrides)
```

- 便捷糖在构建期**脱糖**成 `Requirement` 树；`Requirement` 树是唯一事实源。
- `SERVER`、`END_USER` 这类复合语义不再进库；项目用 `Preset` 或 `Provider` 展开。
- 策略是数据，不是 Go 接口；可以序列化成 manifest、做 diff、做审计。

### 2.3 一个身份：`Principal`

```go
type Principal struct {
    ID     string
    Kind   string              // user / service / api_key / 项目自定义
    Claims map[string][]string // roles / scopes / permissions / tenant / aud
    Attrs  map[string]string
    Raw    any                 // 认证器原始凭证对象
}
```

认证器负责把凭证变成 `Principal`；授权器只消费 `Principal`。两者不互相知道对方实现。

### 2.4 一个决策：`Decider`

```go
type Decider interface {
    Decide(ctx context.Context, req Request) (Decision, error)
}
```

- 默认实现 `RequirementDecider`：按 `Policy` 树求值。
- 项目可替换成 OPA、Cerbos、Casbin、SpiceDB、自研 ABAC/ReBAC 引擎。
- `Decision` 带 `Allow`、可选 `Code`、`Reason`、失败 requirement，供审计与调试。

### 2.5 一个来源：`Provider`

```go
type Provider interface {
    File(protoreflect.FileDescriptor) (FileSpec, bool, error)
    Service(protoreflect.ServiceDescriptor) (ServiceSpec, bool, error)
    Method(protoreflect.MethodDescriptor) (MethodSpec, bool, error)
}
```

- 默认实现读 `grpcapi/v1/policy.proto`。
- torchwood 可以实现 `legacyProvider` 读旧 `method_auth/service_auth`，proto 零改动。
- 配置中心、数据库、外部策略服务也可以做 Provider。

### 2.6 一个装配：`Stage` / `Chain`

```text
Stage{Name, Order, Unary, Stream}
```

- 支持 unary + stream。
- 顺序可配置；默认只做「名字唯一、Order 单调、非空」校验。
- 严格项目用 `AssembleWith` 指定 First/Last/Required。
- recovery/requestid/clientinfo/authn/authz/ratelimit/audit/usage/validate 都是可插拔 Stage。

### 2.7 统一 `Operation`：gRPC 方法与 HTTP 路由同构

这是支持「API 路由装配」的关键抽象。不要只把策略绑在 gRPC method 上：

```go
type Operation struct {
    ID        string        // "/pkg.Svc/Method" 或 "GET /v1/notes/{id}"
    Kind      Kind          // GRPC / HTTP
    Service   string        // gRPC service 或 route group 名
    API       string        // public / internal / partner
    Policy    Policy
    Exposure  Exposure
    Label     string
    Streaming bool          // 仅 gRPC
    Metadata  map[string]string
}
```

- **主模型**：proto Service 的每个 method 是一个 `Kind=GRPC` 的 operation；
  它的 HTTP 路由由 `google.api.http` 派生，不是第二份 operation。
- **次要逃生口**：无法用 `google.api.http` 表达的 health/webhook/static 才注册成
  `Kind=HTTP` 的 extra route。
- `policy.Set` 以 operation ID 为键，authz/guard/manifest 都消费同一张表。
- 这样 proto 路由与少量 extra route 可以共用同一个 `Decider`、同一套错误契约、
  同一份授权矩阵；但普通业务路由不需要手写第二份定义。

> 下文部分历史段落为表述方便仍写 `Method`；落地时统一为 `Operation`，
> `Method` 只是 `Kind=GRPC` 的 operation 的简写。

---

## 3. 开发者体验：三个 Tier 的真实写法

### 3.1 Tier 0：20~30 行跑通

proto：

```protobuf
service NoteService {
  option (grpcapi.v1.service) = {
    default_policy: { authenticated: true }
    default_exposure: EXPOSURE_PUBLIC
  };

  rpc ListPublicNotes(ListPublicNotesRequest) returns (ListPublicNotesResponse) {
    option (google.api.http) = { get: "/v1/public/notes" };
    option (grpcapi.v1.method) = { policy: { anonymous: true } };
  }

  rpc DeleteNote(DeleteNoteRequest) returns (DeleteNoteResponse) {
    option (google.api.http) = { delete: "/v1/notes/{id}" };
    option (grpcapi.v1.method) = {
      policy: { permissions: ["notes.read", "notes.delete"] }
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
    };
  }
}
```

Go：

```go
func main() {
    ctx := context.Background()

    set, err := policy.Build(ctx,
        policy.FromRegistry("notes.api.v1"),
        policy.Options{
            Registry: policy.DefaultRegistry(),
            Vocabulary: policy.NewVocabulary(map[string][]string{
                "scope": {"notes"},
            }),
        })
    if err != nil {
        log.Fatal(err)
    }

    srv, err := server.New(ctx, server.Config{
        Policy:         set,
        Services:       []server.Registration{notesv1.NewNoteServiceRegistration(&impl{})},
        Authenticators: authn.Chain{myAuthenticator}, // JWT / session / API key / mTLS
        GRPCAddr:       ":9060",
        HTTPAddr:       ":8080",
    })
    if err != nil {
        log.Fatal(err)
    }
    log.Fatal(srv.Run(ctx))
}
```

`NewNoteServiceRegistration` 是 6 行手写适配器（或后续 codegen 生成）：

```go
func NewNoteServiceRegistration(impl NoteServiceServer) server.Registration {
    return server.Registration{
        Name:         "notes.api.v1.NoteService",
        Descriptor:   File_notes_proto.Services().ByName("NoteService"),
        RegisterGRPC: func(s *grpc.Server) { RegisterNoteServiceServer(s, impl) },
        RegisterHTTP: func(ctx context.Context, mux *runtime.ServeMux, conn grpc.ClientConnInterface) error {
            return RegisterNoteServiceHandler(ctx, mux, conn)
        },
    }
}
```

> HTTP 路由没有在 `main.go` 里出现，因为全部来自 proto 的 `google.api.http`；
> `server.New` 自动注册 gRPC + gateway，并 mount 到 HTTP handler。
>
> Tier 0 仍然需要一个认证器；全 public 的内部服务可以不传 `Authenticators`，
> 或在 proto 里显式 `anonymous: true`。认证器的最小实现见 `example/`。
>
> `NewXxxRegistration` 也可以由可选的 `protoc-gen-grpcapi` 生成；v3 不把 codegen
> 作为必需步骤，手写适配器只有 6 行。后续插件还可以生成 scope/permission 常量与
> policy manifest。

Tier 0 的默认值：

- 默认 registry：`authenticated` / `claim` / `principal_kind` / `role` / `permission` / `scope`。
- 默认链：recovery → requestid → clientinfo → authn → ratelimit → audit → usage → authz → validate。
- 默认错误体：`{"code","message","error_id"}`。
- 默认 header 策略：安全默认（authorization 拒绝、set-cookie 直透）。
- 默认 gateway marshaler：snake_case（`UseProtoNames=true`）；需要 camelCase 时一行切换。
- 启动断言：所有注册方法必须有策略；public 方法必须有 HTTP 绑定。

### 3.2 Tier 1：逐包组合

```go
set, err := policy.Build(ctx, src, policy.Options{
    Registry: policy.DefaultRegistry(),
    Presets:  []policy.Preset{twServerPreset},
})

surf, err := surface.Build(files, set)

chain, err := interceptor.Assemble(
    interceptor.Recovery(interceptor.RecoveryOptions{Logger: logger}),
    interceptor.RequestID(interceptor.RequestIDOptions{}),
    interceptor.ClientInfo(interceptor.ClientInfoOptions{TrustedProxies: proxies}),
    interceptor.Authn(authn.Chain{jwtAuth, apiKeyAuth}),
    interceptor.Authz(authz.NewInterceptor(set, decider, authz.Options{})),
    interceptor.Validate(interceptor.ValidateOptions{Validator: protovalidateValidator}),
)

mux, err := gateway.NewMux(gateway.MuxOptions{
    ErrorEncoder: gateway.DefaultErrorEncoder(gateway.ErrorOptions{}),
    Headers:      gateway.DefaultHeaderPolicy(),
    Marshaler:    gateway.NewMarshaler(gateway.MarshalerOptions{}), // 默认 snake_case
    ServeMuxOptions: []runtime.ServeMuxOption{
        runtime.WithMetadata(annotator),
    },
})

conn, err := gateway.Dial(ctx, addr, gateway.DialConfig{})
err = gateway.Register(ctx, mux, conn,
    notesv1.NewNoteServiceHTTP,
    usersv1.NewUserServiceHTTP,
)
handler := gateway.NewHandler(gateway.HandlerOptions{
    Gateway: mux,
    Middleware: []gateway.Middleware{
        gateway.Recover(logger),
        gateway.RequestID(),
    },
})
```

Tier 1 的每个默认值都可以替换；没有任何全局单例。`server.New` 只是把这段
「建 mux → 拨号 → 注册 → 套中间件 → 挂服务」做成了默认路径。

### 3.3 Tier 2：项目特化

```go
// 1) 策略来源：读旧扩展 / 配置中心 / 数据库。
type legacyProvider struct{ /* ... */ }
set, err := policy.Build(ctx, src, policy.Options{
    Provider: legacyProvider{},
    Registry: myRegistry,
    Presets:  myPresets,
})

// 2) 决策引擎：OPA / Cerbos / SpiceDB / 自研。
type myDecider struct{ engine Engine }
func (d myDecider) Decide(ctx context.Context, req authz.Request) (authz.Decision, error) {
    // req.Method / req.Principal / req.Request / req.Resource
}

// 3) 对象级授权：从请求中解析资源。
type noteResolver struct{}
func (noteResolver) Resolve(ctx context.Context, req authz.Request) (any, error) {
    // 解析 note id，查库或返回轻量 Resource{Type,ID,Attrs}
}

// 4) 认证：JWT/session/API key/mTLS。
type apiKeyAuth struct{ store APIKeyStore }
func (a apiKeyAuth) Authenticate(ctx context.Context, c authn.Credentials) (*principal.Principal, error) { ... }
```

Tier 2 不需要改库；所有扩展点都是接口。

---

## 4. proto 设计

### 4.1 `policy.proto`

```protobuf
syntax = "proto3";
package grpcapi.v1;
import "google/protobuf/descriptor.proto";

option go_package = "github.com/lynx-go/grpcapi/gen/grpcapi/v1;grpcapiv1";

message APISpec {
  string api = 1;              // public / internal / partner；空 = 默认面
  uint32 schema_version = 2;   // 0 = 1；高于库支持版本即拒绝
  Policy default_policy = 3;   // 可选：文件级默认
  Exposure default_exposure = 4;
}

message ServiceSpec {
  Policy default_policy = 1;
  Exposure default_exposure = 2;
  string label = 3;
}

message MethodSpec {
  Policy policy = 1;           // 声明则默认完全覆盖 service/file 默认
  Exposure exposure = 2;
  string label = 3;            // 文档标签；空 = 自动派生
  string operation_id = 4;     // 可选，覆盖生成器约定
  bool idempotent = 5;         // 仅元数据；行为由可选 idempotency 模块提供
  Deprecation deprecation = 6;

  // true = 方法策略与 service/file 默认按 AND 合并（用于「在默认上收紧」）。
  // 默认 false = 整体替换。方法声明 anonymous 时不允许 inherit。
  bool inherit_default = 7;

  // 仅流式方法有效；默认 OPEN（建立时授权）。
  StreamAuthMode stream_auth = 8;
}

enum StreamAuthMode {
  STREAM_AUTH_MODE_UNSPECIFIED = 0; // = OPEN
  STREAM_AUTH_MODE_OPEN = 1;
  STREAM_AUTH_MODE_PER_MESSAGE = 2;
}

message Deprecation {
  string since = 1;       // 版本或日期
  string sunset = 2;      // 计划移除时间
  string replacement = 3; // 替代方法/链接
}

message Policy {
  // 项目注册的命名策略；展开后与下面的内联约束按 AND 合并。
  string preset = 1;
  map<string, string> preset_args = 2;

  // 显式匿名；与 require/any_of/糖字段互斥（forbid 可共存）。
  bool anonymous = 3;

  // 便捷糖：脱糖成 require。
  bool authenticated = 4;
  repeated string roles = 5;        // match ANY
  repeated string permissions = 6;  // match ALL
  repeated string scopes = 7;       // match ANY

  // 通用逃生口。
  repeated Requirement require = 8;
  repeated Alternative any_of = 9;
  repeated Requirement forbid = 10;
}

message Alternative {
  bool authenticated = 1;
  repeated string roles = 2;
  repeated string permissions = 3;
  repeated string scopes = 4;
  repeated Requirement require = 5;
}

message Requirement {
  string kind = 1;             // authenticated / claim / principal_kind / 项目自定义
  string vocabulary = 2;       // 缺省 = kind
  Match match = 3;             // 未指定 = kind 默认
  repeated string values = 4;
  map<string, string> params = 5;
}

enum Match {
  MATCH_UNSPECIFIED = 0;
  MATCH_ANY = 1;
  MATCH_ALL = 2;
}

enum Exposure {
  EXPOSURE_UNSPECIFIED = 0;
  EXPOSURE_INTERNAL = 1;    // 仅 gRPC，不进 HTTP/OpenAPI/SDK
  EXPOSURE_PUBLIC = 2;      // HTTP + 文档 + SDK
  EXPOSURE_DEPRECATED = 3;  // 仍可用，文档标记弃用
  EXPOSURE_HIDDEN = 4;      // 可调用但不进公开文档
}

extend google.protobuf.FileOptions    { APISpec api = 53001; }
extend google.protobuf.ServiceOptions { ServiceSpec service = 53002; }
extend google.protobuf.MethodOptions  { MethodSpec method = 53003; }
```

> 字段号刻意选 53001~53003，避开 v2 `authz.proto` 的 52301/52302 与 torchwood
> 历史号段 52001/52002。torchwood 迁移期可能同时加载旧扩展与新扩展；扩展字段号
> 在 wire 层没有 package 命名空间，同号不同型会导致 `GetExtension` 静默跳过，
> 注解丢失后权限可能变宽。宁可换号，不做双读。

### 4.2 脱糖规则

| 糖 | 脱糖结果 |
|---|---|
| `anonymous: true` | 显式公开；不再生成任何 require |
| `authenticated: true` | `Requirement{kind:"authenticated"}` |
| `roles: [a,b]` | `Requirement{kind:"role", match:ANY, values:[a,b]}` |
| `permissions: [a,b]` | `Requirement{kind:"permission", match:ALL, values:[a,b]}` |
| `scopes: [a,b]` | `Requirement{kind:"scope", match:ANY, values:[a,b]}` |
| `any_of: [{roles:[...]}, {scopes:[...]}]` | `AnyOf` 组内按上述规则脱糖并 AND |
| `preset: "tw.server", preset_args:{...}` | 展开为 `Policy`，再与内联字段 AND |
| `require: [{kind:"tenant", values:["acme"]}]` | 原样保留 |

约束：

- `anonymous` 与 `require/any_of/authenticated/roles/permissions/scopes` 互斥。
- `preset` 展开后如果仍是 `anonymous`，则不允许再叠加内联 require。
- `forbid` 只接受通用 `Requirement`，不提供糖；拒绝规则必须显式。
- 空策略（无 anonymous、无 require、无 any_of、无糖）→ 构建失败。
- 糖字段的 `kind` 名可由项目 registry 覆盖（例如把 `roles` 映射到 `groups` claim），但默认名是约定。

### 4.3 策略作者速查

```protobuf
// 公开
policy: { anonymous: true }

// 任意已认证主体
policy: { authenticated: true }

// 任一角色
policy: { roles: ["admin", "operator"] }

// 全部权限
policy: { permissions: ["notes.read", "notes.delete"] }

// 任一 scope
policy: { scopes: ["notes:write"] }

// admin 角色 或 notes:admin scope
policy: { any_of: [ { roles: ["admin"] }, { scopes: ["notes:admin"] } ] }

// 项目自定义维度
policy: { require: [ { kind: "tenant" values: ["acme"] } ] }

// 复用项目策略
policy: { preset: "tw.server" preset_args: { scope: "echoes:write" } }
```

| 场景 | 推荐写法 |
|---|---|
| 大多数简单方法 | service/file default + 少量糖 |
| 重复的复合策略 | Preset |
| 旧系统 / 配置中心 / 数据库 | Provider |
| 外部引擎 / 对象级授权 | Decider + ResourceResolver |
| 极复杂谓词 | 自定义 Kind 或可选 CEL |
| 临时收紧某个方法 | 内联 require/forbid |

### 4.4 标签派生

`label` 用于 OpenAPI 扩展与文档矩阵。未显式设置时按以下顺序派生：

1. 显式 `MethodSpec.label`
2. `Policy.preset`
3. 仅 `anonymous` → `"public"`
4. 仅 `authenticated` → `"authenticated"`
5. 仅 `roles` → `"role"`
6. 仅 `permissions` → `"permission"`
7. 仅 `scopes` → `"scope"`
8. 其他 → `"custom"`

项目可以覆盖 `Labeler`。标签只用于文档分类，不参与授权判断。

### 4.5 预设示例

torchwood 想保留旧写法，可以注册 preset：

```protobuf
option (grpcapi.v1.method) = {
  policy: {
    preset: "tw.server"
    preset_args: { scope: "echoes:write", roles: "admin" }
  }
};
```

```go
var twServer = policy.Preset{
    Name: "tw.server",
    Build: func(args map[string]string) (policy.Policy, error) {
        roles := splitCSV(args["roles"])
        scope := args["scope"]
        return policy.Policy{
            AnyOf: [][]policy.Requirement{
                {policy.Role(roles...)},
                {policy.Scope(scope)},
            },
        }, nil
    },
}
```

库不知道 `tw.server` 的语义；只知道它必须存在、必须能展开、展开结果必须通过通用校验。

### 4.6 schema 演进

- `APISpec.schema_version` 高于库支持版本 → 构建失败。
- 默认 Provider 检测扩展消息的 unknown fields；非空 → 构建失败。
- 这修掉 v2 DESIGN §11 的「新字段 + 旧库 = 权限静默变宽」问题。
- 新增字段必须是可选且有默认语义；破坏性变更走 0.x minor + migration note。

---

## 5. Go API

### 5.1 `policy` 核心

```go
package policy

type Match int

type Requirement struct {
    Kind       string
    Vocabulary string
    Match      Match
    Values     []string
    Params     map[string]string
}

type Policy struct {
    Preset     string
    PresetArgs map[string]string
    Anonymous  bool
    Require    []Requirement
    AnyOf      [][]Requirement
    Forbid     []Requirement
}

type Exposure int

const (
    ExposureInternal Exposure = iota + 1
    ExposurePublic
    ExposureDeprecated
    ExposureHidden
)

type StreamAuthMode int

const (
    StreamAuthOpen       StreamAuthMode = iota + 1 // 默认
    StreamAuthPerMessage
)

type Kind int
const (
    KindGRPC Kind = iota + 1
    KindHTTP
)

// Operation.Policy 始终是「preset 展开 + inherit 合并」后的有效策略；
// Preset/PresetArgs 只保留诊断信息，不参与求值，manifest 输出时清空。
type Operation struct {
    ID          string // "/pkg.Svc/Method" 或 "GET /v1/notes/{id}"
    Kind        Kind
    Service     string
    API         string
    Policy      Policy
    Exposure    Exposure
    Label       string
    OperationID string // 文档生成器的 operationId（可选）
    Streaming   bool   // 仅 KindGRPC
    StreamAuth  StreamAuthMode // 仅流式：OPEN / PER_MESSAGE
    Metadata    map[string]string
}

// Method 是 gRPC operation 的简写别名（Kind=GRPC）。
type Method = Operation

type Set struct { /* immutable */ }

func NewSet(ops ...Operation) (*Set, error) // 空集合也合法（纯 extra route 服务）
func (s *Set) Get(id string) (Operation, bool)
func (s *Set) IsAnonymous(id string) bool // authn 的 IgnoreOnAnonymous 用
func (s *Set) Operations() []Operation
func (s *Set) APIs() []string
func (s *Set) FilterAPI(api string) *Set
func (s *Set) WithOperations(ops ...Operation) (*Set, error) // 合并 extra route 策略
func (s *Set) Registry() *Registry // Build 时的 registry，供默认 Decider 复用
func (s *Set) Manifest() Manifest

// 稳定字符串，用于矩阵/日志/manifest diff。
func Format(p Policy) string
```

Manifest 是给 CI、文档和非 Go 消费者用的稳定快照（不含 descriptor）。v3.0 默认在
CI 生成 `policy.manifest.json` 并 diff；**不**作为运行时策略源，避免第二份策略
定义：

```go
type Manifest struct {
    Version int
    APIs    []ManifestAPI
}
type ManifestAPI struct {
    Name       string
    Operations []ManifestOperation
}
type ManifestOperation struct {
    ID         string
    Kind       string // grpc / http
    Exposure   string
    Label      string
    StreamAuth string // open / per_message（仅流式）
    Policy     Policy
}
```

便捷构造器（测试与动态策略用）：

```go
// Policy 构造
policy.AnonymousPolicy()
policy.AnyOf(...)
policy.Require(...)
policy.Forbid(...)

// Requirement 构造（默认 kind/claim/match 约定）
policy.RequireAuthenticated()
policy.Role("admin")
policy.Permission("notes.read", "notes.delete")
policy.Scope("notes:write")
```

### 5.2 `Source`

```go
type Source interface {
    Files(ctx context.Context) ([]protoreflect.FileDescriptor, error)
}

func FromFiles(files ...protoreflect.FileDescriptor) Source
func FromRegistry(prefixes ...string) Source
func FromFileDescriptorSet(path string) Source
func FromDescriptorSet(*descriptorpb.FileDescriptorSet) Source
```

`FromRegistry` 按包前缀遍历 `protoregistry.GlobalFiles`，避免手工维护文件清单。`FromFileDescriptorSet` 支持 `buf build -o image.bin` 产物。

### 5.3 `Provider`

```go
type FileSpec struct {
    API           string
    SchemaVersion uint32
    DefaultPolicy *Policy
    DefaultExposure Exposure
}
type ServiceSpec struct {
    DefaultPolicy   *Policy
    DefaultExposure Exposure
    Label           string
}
type MethodSpec struct {
    Policy         *Policy
    Exposure       Exposure
    Label          string
    OperationID    string
    InheritDefault bool           // true = AND(default, policy)；false = 整体替换
    StreamAuth     StreamAuthMode // 仅流式；默认 Open
}

type Provider interface {
    File(protoreflect.FileDescriptor) (FileSpec, bool, error)
    Service(protoreflect.ServiceDescriptor) (ServiceSpec, bool, error)
    Method(protoreflect.MethodDescriptor) (MethodSpec, bool, error)
}
```

默认：

```go
import "github.com/lynx-go/grpcapi/policy/protopolicy"

policy.Options{
    Provider: protopolicy.New(protopolicy.Options{
        AllowUnknownFields: false, // 零值安全：默认拒绝
        MaxSchemaVersion:   1,
    }),
}
```

### 5.4 `RequirementKind`

```go
type Kind struct {
    Name string

    DefaultMatch Match
    RequiresVocabulary bool

    Validate func(req Requirement, vocab Vocabulary) error

    // 运行期求值；nil 表示只声明/校验，由自定义 Decider 消费。
    Evaluate func(ctx context.Context, ec EvalContext, req Requirement) (bool, error)
}

type EvalContext struct {
    Operation Operation
    Principal *principal.Principal
    Request   any // proto.Message（gRPC）或 *http.Request（extra route）
    Metadata  map[string][]string
    Resource  any
}
```

内置 Kind 构造：

```go
policy.KindAuthenticated() // kind="authenticated"
policy.KindClaim()         // kind="claim"，params{name:...}
policy.KindPrincipal()     // kind="principal_kind"

policy.ClaimKind("role", "roles", policy.MatchAny)
policy.ClaimKind("permission", "permissions", policy.MatchAll)
policy.ClaimKind("scope", "scopes", policy.MatchAny) // 默认精确匹配
```

`policy.DefaultRegistry()` 把上面这些一次性注册好；项目只需要在 claim 名不同时覆盖。

`policy/scope` 是可选预设，提供 `resource` / `resource:op` 语义（兼容 v2 的
`resource.op` 写法；资源名本身允许包含点号）：

```go
scope.Kind(scope.Options{
    VocabularyDomain: "scope",
    RequireVocabulary: true,
    AllowWildcard: true,
})
```

默认 registry 不解析 scope 语法，只做精确 claim 匹配；这样不会把 torchwood 的 scope 语言强加给所有项目。

### 5.5 `Preset`

```go
type Preset struct {
    Name  string
    Build func(args map[string]string) (Policy, error)
}
```

展开：

- 最大深度 8，检测环。
- 展开结果与内联约束按 AND 合并。
- 展开后空策略且非 anonymous → 失败。
- 参数校验失败 → 错误带 preset 名与方法名。

### 5.6 `Build`

```go
type Options struct {
    Provider       Provider
    Registry       *Registry
    Vocabulary     Vocabulary
    Presets        []Preset
    DisableStreaming bool // 零值 = 允许；纯 unary 项目可显式关闭
    Rules            []Rule

    // 框架服务豁免：默认跳过 grpc.health.v1 / grpc.reflection /
    // grpc.channelz.v1，不要求业务策略。
    FrameworkExempt func(fullMethod string) bool

    // 按 package 前缀推断 API 面，省去每个文件写 APISpec.api。
    APIResolver func(protoreflect.FileDescriptor) string

    // 只构建这些 service；server.New 用 PolicySource 时自动填入已注册 service，
    // 避免共享 package 里的未注册 service 触发 AllowUnregisteredPolicies。
    IncludeServices []protoreflect.FullName

    // 非空时只构建这些 proto package 下的文件；buf image 含依赖时用它收窄。
    PackagePrefixes []string
}

func Build(ctx context.Context, src Source, opts Options) (*Set, error)
```

`Build` 按 `fd.Path()` 去重文件，避免 `FromRegistry` + `FromFiles` 混用时重复方法报错。

失败清单（全部聚合）：

1. 方法无策略、无 service/file 默认。
2. `anonymous` 与 require/any_of/糖混用；`inherit_default` 与 `anonymous` 混用。
3. 未知 kind / preset；preset 展开循环或超过深度。
4. 词表缺失或值越界。
5. `schema_version` 过高；同一次 Build 内文件版本不一致。
6. 扩展 unknown fields 非空。
7. 流式方法且 `DisableStreaming=true`。
8. 重复方法。
9. 项目 `Rule` 违例。
10. `any_of` 中存在空组（空组会恒真，必须拒绝）。
11. `authenticated` 携带 values/params；`claim` 缺少 `params.name`。
12. 值型 kind（role/permission/scope/principal_kind）values 为空。
13. `Requirement.Vocabulary` 指定的 domain 未注册但 kind 要求词表。
14. 同一 kind 在 registry 中重复注册。

### 5.7 `Rule`

```go
type Rule interface {
    Name() string
    CheckMethod(Method) error
    CheckSet(*Set) error
}
```

项目断言（值域、面前缀、不变量）继续可注入。`NoDeadValues` 是可选 Rule，不是内置强制。

### 5.8 求值

```go
package authz

type Request struct {
    policy.EvalContext
    Stream bool
}

type Decision struct {
    Allow   bool
    Code    codes.Code // 可选；零值由拦截器推导
    Reason  string
    Failed  *policy.Requirement
    Obligations map[string]string // 外部引擎附加建议（可选）
}

type Decider interface {
    Decide(ctx context.Context, req Request) (Decision, error)
}

type RequirementDecider struct { /* set + registry */ }

// 默认 Decider：从 Set 取 registry，不需要项目再传一份。
func NewRequirementDecider(set *policy.Set) (*RequirementDecider, error)
```

求值顺序：

1. `forbid` 任一命中 → deny（deny-overrides）。
2. `require` 未全满足 → deny。
3. `any_of` 非空且没有一组全满足 → deny。
4. 其余 allow。
5. `anonymous` 不要求 Principal；非 anonymous 且 Principal 为 nil 时，拦截器返回
   `Unauthenticated`（而不是 403）。

错误码：

- 缺 Principal → `Unauthenticated`
- 有 Principal 但不足 → `PermissionDenied`
- 运行时缺策略 → `Internal`（配置漂移）
- 空策略 / 未展开 preset → `Internal`，不能静默放行
- 求值器错误：若已是显式 gRPC status（如外部引擎返回 `Unavailable` /
  `PermissionDenied`），原样透传；否则包成 `Internal`，绝不 fail-open。
- `Decision.Reason` 只进日志/审计，不下发客户端。

### 5.9 对象级授权

```go
type ResourceResolver interface {
    Resolve(ctx context.Context, req Request) (any, error)
}

type InterceptorOptions struct {
    ResourceResolver ResourceResolver
    MissingPrincipalCode codes.Code // 默认 Unauthenticated
    DeniedCode           codes.Code // 默认 PermissionDenied
    MissingPolicyCode    codes.Code // 默认 Internal
    OnDecision           func(ctx context.Context, op policy.Operation, d Decision)
    StreamMode           StreamMode // 全局默认；policy.Operation.StreamAuth 按方法覆盖
}

// Options 是 gRPC 拦截器/HTTP 中间件共享的授权选项。
type Options = InterceptorOptions

func NewInterceptor(set *policy.Set, decider Decider, opts InterceptorOptions) (*Interceptor, error)
func (i *Interceptor) Unary() grpc.UnaryServerInterceptor
func (i *Interceptor) Stream() grpc.StreamServerInterceptor
```

- 拦截器在调用 `Decider` 前解析资源，写入 `req.Resource`。
- 解析失败 → `Internal` 或项目指定 code。
- 默认不解析；方法级策略不需要额外成本。
- 自定义 `RequirementKind` 或 `Decider` 可以用 `req.Request` / `req.Resource` 做
  owner/tenant/relation 判断。
- 这是接入 SpiceDB/Zanzibar、Cerbos derived roles、自研 ABAC 的入口。

### 5.10 `authn`

```go
package authn

type Credentials struct {
    FullMethod string // "/pkg.Svc/Method"，认证器可按方法做策略
    Metadata   metadata.MD
    Peer       *peer.Peer
    Bearer     []string
    APIKeys    []string
    Cookies    []string
    TLS        *tls.ConnectionState
}

type Authenticator interface {
    Name() string
    // (nil, nil) = 不认识，继续尝试下一个；
    // (nil, err) = 认识但拒绝，立即 Unauthenticated。
    Authenticate(ctx context.Context, c Credentials) (*principal.Principal, error)
}

type Chain []Authenticator

// 凭证提取也是特化点：项目可能用自定义头、mTLS、cookie 组合。
type Extractor interface {
    Extract(ctx context.Context, fullMethod string, md metadata.MD, peer *peer.Peer) (Credentials, error)
}

func DefaultExtractor() Extractor

// Enricher 在认证成功后运行（例如 admin store 补充角色）。
type Enricher interface {
    Name() string
    Enrich(ctx context.Context, p *principal.Principal) error
}

type Options struct {
    MultipleCredentialPolicy MultipleCredentialPolicy // Reject（默认）/ FirstWins
    // 默认 Reject：即使方法 public，无效凭证也返回 401。
    // 需要「public 面忽略无效凭证」的项目显式改为 IgnoreOnAnonymous。
    InvalidCredentialPolicy InvalidCredentialPolicy
    // IgnoreOnAnonymous 需要它判断方法是否显式公开；Tier 0/1 由装配层注入。
    IsAnonymous func(fullMethod string) bool
    Extractor   Extractor
    Enrichers   []Enricher // 顺序执行；失败按认证后端故障处理
    OnFailure   func(ctx context.Context, err error)
}
```

语义：

- 无凭证：不报错，继续；授权拦截器决定是否需要 Principal。
- 无效凭证：即使方法 public 也返回 `Unauthenticated`，不降级。
- 认证后端故障（JWKS 拉取失败、DB 不可用）必须返回 `Unavailable`/`Internal`，
  不能伪装成 401；否则客户端会误以为凭证错误并反复重试。
- 多凭证同时出现：默认拒绝。
- 认证成功：`principal.With(ctx, p)`；随后按序运行 `Enrichers`。

#### 5.10.1 参考实现（v3.0 提供）

| 包 | 提供 | 项目提供 |
|---|---|---|
| `authn/jwt` | token 解析/验签、JWKS 缓存、issuer/audience 校验、claims→Principal | JWKS URL、issuer、audience、claims 映射 |
| `authn/session` | cookie 解析、签名/加密、session store 接口、TTL/轮换 | session 后端（Redis/DB/内存） |
| `authn/apikey` | key 格式、哈希查找、常量时间比较、scope 注入、过期/吊销 | key store（DB/缓存） |
| `authn/admin` | admin store 补充角色、停用标记、与 claims 合并 | admin store |
| `csrf` | double-submit cookie + SameSite + Origin/Referer 校验 | cookie/header 名称、密钥 |

```go
// authn/jwt
type Verifier interface { Verify(ctx context.Context, token string) (Claims, error) }
type Config struct {
    Verifier             Verifier // 或 KeyFunc+Issuer/Audience
    KeyFunc              jwt.Keyfunc
    Issuer, Audience     string
    ClockSkew            time.Duration
    ValidMethods         []string
    AllowMissingExpiration bool
    Claims               func(Claims) (*principal.Principal, error)
}
func New(Config) (*Authenticator, error)
func NewJWKS(url string) *JWKS // JWKS 拉取/缓存 + jwt.Keyfunc

// authn/session
type Store interface {
    Get(ctx context.Context, id string) (*Session, error)
    Create(ctx context.Context, s *Session) error
    Touch(ctx context.Context, id string, ttl time.Duration) error
    Delete(ctx context.Context, id string) error
}
type Config struct {
    CookieName string
    Store      Store
    SigningKey []byte // HMAC；cookie 只放 session ID + 签名
    TTL        time.Duration
    SameSite   http.SameSite
    Secure     bool
}
func New(Config) (*Authenticator, error)
func (a *Authenticator) Issue(ctx, w, p) error
func (a *Authenticator) Destroy(ctx, w, r) error
func (a *Authenticator) RequiresCSRF() bool // server.New 用来强制 CSRF

// authn/apikey
type Store interface { Lookup(ctx context.Context, hash string) (*Key, error) }
type Key struct {
    ID, PrincipalID string
    Scopes          []string
    ExpiresAt       time.Time
    Revoked         bool
    Claims          map[string][]string
}
func New(Config) (*Authenticator, error)
func Hash(raw string) string // SHA-256 hex

// authn/admin
type Store interface { Get(ctx context.Context, principalID string) (*Admin, error) }
type Admin struct { Roles []string; Suspended bool; Attrs map[string]string }
func New(Config) (*Enricher, error)
```

**Admin 角色合并规则（两者都有）：**

- JWT/session 里的 admin 角色写入 `admin_roles`，**不写入普通 `roles`**。
- admin store 的角色与 claims 取并集；store 不可用 → `Unavailable`，不能当成
  「没有 admin 角色」。
- `Suspended=true` → 注入 `admin_suspended=true` claim；`admin` preset 用
  `forbid` 拒绝。
- 普通用户角色与 admin 角色分开，避免「JWT 里带了 admin role 就自动成为后台
  管理员」的权限混淆。

**CSRF（session/cookie 必配）：**

- Double-submit cookie：session cookie `HttpOnly + Secure + SameSite=Lax/Strict`，
  CSRF cookie 可被 JS 读取，请求头 `X-CSRF-Token` 与 cookie 值一致。
- 只校验 unsafe method（POST/PUT/PATCH/DELETE）；GET/HEAD/OPTIONS 跳过。
- 额外校验 `Origin`/`Referer`，允许列表由项目配置。
- `session.Authenticator` 实现 `RequiresCSRF() bool`；`server.New` 发现 session
  认证但没有 CSRF 配置 → 启动失败（`AllowNoCSRF` 可放宽）。

```go
type Stage struct {
    Name   string
    Order  int
    Unary  grpc.UnaryServerInterceptor
    Stream grpc.StreamServerInterceptor
}

type ChainOptions struct {
    First    string
    Last     string
    Required []string
}

func Assemble(stages ...Stage) (*Chain, error)
func AssembleWith(opts ChainOptions, stages ...Stage) (*Chain, error)

func (c *Chain) Unary() []grpc.UnaryServerInterceptor
func (c *Chain) Stream() []grpc.StreamServerInterceptor
func (c *Chain) ServerOptions() []grpc.ServerOption
func (c *Chain) Has(name string) bool       // unary 侧
func (c *Chain) HasStream(name string) bool // stream 侧
```

内置 Stage 构造器：

```go
interceptor.Recovery(...)
interceptor.RequestID(...)
interceptor.ClientInfo(...)
interceptor.Authn(...)
interceptor.Authz(...)
interceptor.RateLimit(...)
interceptor.Audit(...)
interceptor.Usage(...)
interceptor.Validate(...)
```

顺序常量：

```go
const (
    OrderRecovery  = 0
    OrderRequestID = 10
    OrderClientInfo = 20
    OrderAuthn     = 30
    OrderRateLimit = 40
    OrderAudit     = 50
    OrderUsage     = 60
    OrderAuthz     = 70
    OrderValidate  = 80
)
```

`Validate` 支持 stream：包装 `ServerStream.RecvMsg`，逐条校验 client-streaming/bidi 消息；server-streaming 的单个请求也会被校验。

stream 的通用做法：

- `clientinfo` / `authn` / `authz` / `requestid` 包装 `ServerStream.Context()`，
  让 handler 内拿到的 ctx 与 unary 一致。
- `authz` 的粒度优先取 `policy.Operation.StreamAuth`；未设置时用
  `InterceptorOptions.StreamMode`，再默认 `OPEN`。
- `validate`：client/bidi 逐条 `RecvMsg` 校验；server-streaming 只校验首个请求。
- `usage`/`audit` 在 stream 建立与结束各结算一次；per-message 模式可选逐条事件。
- 所有包装器必须转发 `SendMsg`/`RecvMsg`/`SetHeader`/`SetTrailer`，不要只包 Context。

限流/审计/用量是常见但非核心的能力，只提供 SPI 与 no-op 默认：

```go
type Limiter interface {
    Allow(ctx context.Context, key string, cost int) (bool, error)
}
type Auditor interface {
    Record(ctx context.Context, event audit.Event) error
}
type Meter interface {
    Add(ctx context.Context, event usage.Event) error
}
```

项目可以只实现其中一个，或直接不装对应 Stage。

### 5.12 `gateway`

```go
package gateway

type ErrorResponse struct {
    Status  int
    Body    any
    Headers http.Header
}

type ErrorEncoder interface {
    Encode(ctx context.Context, err error) ErrorResponse
}

type ErrorEncoderFunc func(context.Context, error) ErrorResponse

// WriteError 把 Encoder 的结果写到 HTTP 响应；authn/authz HTTP 中间件共用。
func WriteError(w http.ResponseWriter, r *http.Request, err error, e ErrorEncoder)

func DefaultErrorEncoder(opts ErrorOptions) ErrorEncoder
func NewEncoderErrorHandler(e ErrorEncoder) runtime.ErrorHandlerFunc // nil → DefaultErrorEncoder

type ErrorOptions struct {
    CodeToHTTP map[codes.Code]int
    CodeString func(codes.Code) string
    Sanitize   func(codes.Code) bool // 默认 Internal/Unknown
    ErrorID    func() string
    Logger     *slog.Logger
    // 零值安全：默认提取 RetryInfo 写 Retry-After；显式关闭才设为 true。
    DisableRetryAfter bool
}
```

错误写出的边界语义：

- `ErrorResponse.Status == 0` → 按 500 处理（不能写出非法状态码）。
- `Body == nil` → 只写状态与 headers，不写 body。
- `Headers` 原样写入；`Content-Type` 默认 `application/json`，可覆盖。
- `Encode` 返回错误时不能 panic；记录日志并退回通用 500。
- `Retry-After` 只对 429 生效，值至少 1 秒。

Header 策略：

```go
type HeaderPolicy struct {
    // 默认 {"authorization", "x-grpcapi-client-ip"}：
    // 前者避免双写 401，后者防止客户端伪造内部 client-ip。
    Deny       []string
    Allow      []string // 默认 cookie / x-api-key / x-request-id / idempotency-key
    Direct     []string // 默认 set-cookie
    FallbackIn func(string) (string, bool)
    FallbackOut func(string) (string, bool)
}

func DefaultHeaderPolicy() HeaderPolicy
```

`Deny` 优先于 `Allow`；同一头同时出现时拒绝。`Direct` 只影响出站。

Mux / Handler：

```go
type MuxOptions struct {
    ErrorEncoder ErrorEncoder   // 新式；优先于 ErrorHandler
    ErrorHandler runtime.ErrorHandlerFunc // 旧式适配
    HeaderPolicy *HeaderPolicy  // 非 nil 时接管入/出站策略
    Marshaler    runtime.Marshaler
    IncomingExtra []string
    OutgoingDirect []string
    ServeMuxOptions []runtime.ServeMuxOption
    // server.New 用它注入 x-grpcapi-client-ip。
    Metadata func(context.Context, *http.Request) metadata.MD
}

// 零值安全：ErrorEncoder/ErrorHandler 都 nil → DefaultErrorEncoder；
// HeaderPolicy nil → 旧 matcher；Marshaler nil → NewMarshaler。
func NewMux(o MuxOptions) *runtime.ServeMux

type Middleware = func(http.Handler) http.Handler

type HandlerOptions struct {
    Gateway     *runtime.ServeMux
    Middleware  []Middleware
    ExtraRoutes func(*http.ServeMux)
}

func NewHandler(o HandlerOptions) http.Handler
```

Dial：

```go
type DialConfig struct {
    TLS         *tls.Config
    Target      func(string) string
    Dialer      func(ctx context.Context, addr string) (net.Conn, error)
    DialOptions []grpc.DialOption
}

func Dial(ctx context.Context, addr string, cfg DialConfig) (*grpc.ClientConn, error)
```

Marshaler 选项：

```go
type MarshalerOptions struct {
    // 零值安全：默认 false = UseProtoNames (snake_case)。
    // 需要 protojson 标准 camelCase 时设为 true 或用 CamelCaseMarshaler()。
    UseJSONNames    bool
    EmitUnpopulated bool
    // 默认 false = discard unknown（向前兼容）；严格项目设为 true。
    RejectUnknownFields bool
}

func NewMarshaler() runtime.Marshaler // 默认 snake_case
func NewMarshalerWithOptions(o MarshalerOptions) runtime.Marshaler
func CamelCaseMarshaler() runtime.Marshaler
```

### 5.13 `surface`

```go
package surface

type HTTPBinding struct {
    Verb         string
    Path         string
    Body         string
    ResponseBody string
    BindingIndex int
}

type Operation struct {
    Operation  policy.Operation
    Service    protoreflect.ServiceDescriptor
    Descriptor protoreflect.MethodDescriptor
    Input      protoreflect.MessageDescriptor
    Output     protoreflect.MessageDescriptor
    HTTP       []HTTPBinding
    Streaming  bool
}

type Surface struct { /* ... */ }

func Build(files []protoreflect.FileDescriptor, set *policy.Set) (*Surface, error)

// server.New 只有 ServiceDescriptor，不需要调用方再收集 files。
func BuildFromServices(services []protoreflect.ServiceDescriptor, set *policy.Set) (*Surface, error)

func (s *Surface) Operations() []Operation
func (s *Surface) Services() []protoreflect.ServiceDescriptor
func (s *Surface) OperationsByAPI(api string) []Operation
func (s *Surface) Policy() *policy.Set

type RouteInfo struct {
    Method     string
    ProtoPath  string // proto 中声明的路径
    Path       string // 加上 API/Service 前缀后的最终部署路径
    FullMethod string // proto 路由有；extra route 为空
    API        string
    Exposure   policy.Exposure
    Label      string
    Source     string // "proto" / "extra"
}
```

`Surface` 与 `policy.Build` 共用同一套框架服务豁免；`grpc.health.v1` /
`grpc.reflection` / `grpc.channelz.v1` 不进入业务 Surface，也不参与 SDK/文档守卫。

HTTP 绑定提取：

- 主规则与 `additional_bindings` 都提取；`BindingIndex` 稳定。
- `body` / `response_body` 原样记录，供后续 schema 级守卫使用。
- `custom` verb 保留 `kind:path` 形态。
- `google.api.http.selector` 如出现，按 selector 关联到目标方法；否则用方法自身规则。
- 路径归一（重复斜杠、尾斜杠）由 `surface`/`guard` 共用同一个 helper。

暴露面断言：

- `PUBLIC` / `DEPRECATED` 必须有 `google.api.http`。
- `INTERNAL` 不应有 HTTP 绑定。
- `UNSPECIFIED` 继承 file/service；仍未指定 → 失败。
- `HIDDEN` 可有 HTTP 绑定，但不进公开文档。
- **client-streaming / bidi + `PUBLIC`/`DEPRECATED` → 启动失败**：grpc-gateway
  不能把这些流转码成普通 HTTP。只能标 `INTERNAL`/`HIDDEN`，或等未来
  Connect/WebSocket 适配器。
- server-streaming 可 `PUBLIC`，但生成 handler 必须使用流式响应；
  `surface` 记录该绑定，guard 按普通 operation 校验。

### 5.14 `guard`

```go
package guard

type Document struct {
    Path        string
    Raw         []byte
    TopLevel    map[string]any
    Operations  []DocumentOperation
    Definitions map[string]json.RawMessage // v2 definitions / v3 components.schemas
}

type DocumentOperation struct {
    ID                 string
    Verb               string
    Path               string
    Metadata           map[string]any
    DefaultResponseRef string
    Raw                json.RawMessage
}

type Loader interface {
    Load(ctx context.Context) ([]Document, error)
}

func OpenAPIv2(fsys fs.FS, opts OpenAPIv2Options) (Loader, error)
func OpenAPIv3(fsys fs.FS, opts OpenAPIv3Options) (Loader, error)

type MatchOptions struct {
    MetadataKey      string // 默认 "x-grpcapi-policy"
    // 零值安全：默认检查 metadata；显式跳过才设为 true。
    SkipMetadata     bool
    Label            func(policy.Operation) string
    Documented       []policy.Exposure // 默认 PUBLIC + DEPRECATED
    Ignore           func(DocumentOperation) bool
    ErrorRef         func(Document, DocumentOperation) (string, bool)
    // 部署前缀与 proto 路径的差异：非空时只用于匹配，不修改文档。
    Prefix           string
    NormalizePath    func(string) string // 默认去尾斜杠/折叠重复斜杠
    // 零值安全：默认开启 operationId 兜底；显式关闭才设为 true。
    DisableOperationIDFallback bool
    CheckTopLevel    bool
    // ServiceLabel 在 CheckTopLevel 时返回服务默认 label。
    ServiceLabel     func(service string) (string, bool)
    MinDocuments     int
    MinOperations    int
}

func AssertDocuments(t testing.TB, l Loader, s *surface.Surface, o MatchOptions)
```

`AssertDocuments` 的顺序：

1. 从 `Surface` 生成期望操作（仅 `Documented` 暴露面）。
2. 逐文档操作按 `verb+path` 匹配；未命中按 `Ignore` 处理。
3. 比对有效 label（op 级优先，缺省回落文档顶层）。
4. 比对 `default` 响应引用（若配置 `ErrorRef`）。
5. 反向覆盖：每个期望操作至少出现一次。
6. 文档只含单个 service 时，比对顶层 default label。
7. `MinDocuments` / `MinOperations` 防空转。

单条断言仍保留：

```go
func AssertJSONNaming(t testing.TB, docs []Document, rule NamingRule)
func AssertNoSchema(t testing.TB, docs []Document, banned string)
func AssertMethodCount(t *testing.T, s *surface.Surface, api, prefix string, want int)
func AssertServiceCoverage(t *testing.T, s *surface.Surface, api, prefix string, client any, o SDKOptions)
func RenderMatrix(set *policy.Set, o MatrixOptions) ([]byte, error)
func AssertDocUnchanged(t *testing.T, rendered []byte, path string)
```

### 5.15 `guard.Suite`：一条命令跑全部守卫

```go
type SuiteConfig struct {
    Surface  *surface.Surface
    Docs     Loader
    Policy   MatchOptions // 零值由 Suite 填充默认（SkipMetadata=false 等）
    Naming   NamingRule
    Banned   []string
    Matrix   *MatrixConfig
    Manifest *ManifestConfig // 快照锁：权限变化必须显式更新
    SDK      *SDKConfig
    MinDocuments  int
    MinOperations int
}

type SDKConfig struct {
    API, Prefix string
    Client      any
    Options     SDKOptions
    WantMethods int
}

type ManifestConfig struct {
    Path string // 磁盘上的 policy manifest JSON
}
type MatrixConfig struct {
    Path    string
    Options MatrixOptions
}

func Run(t *testing.T, cfg SuiteConfig)
```

`Run` 用 `t.Run` 分成子测试：

```text
openapi/policy
openapi/naming
openapi/banned
sdk/coverage
manifest/snapshot
matrix/snapshot
```

零值字段跳过对应检查；`Surface` 必填。这样项目可以在一个测试文件里获得全部一致性保护。

### 5.16 `server`：可选 facade

```go
package server

type HTTPRegisterFunc func(context.Context, *runtime.ServeMux, grpc.ClientConnInterface) error

type Registration struct {
    API          string // 必须与 APISpec.api 一致；空 = 默认面
    Prefix       string // 可选 HTTP 前缀
    Name         string
    Descriptor   protoreflect.ServiceDescriptor
    RegisterGRPC func(*grpc.Server)
    RegisterHTTP HTTPRegisterFunc
    // 显式允许 API 面不一致（默认 false，防止 internal 误挂 public）。
    AllowAPIMismatch bool
}

// RouteInfo 定义在 surface 包，避免 guard 依赖 server facade。
// server.Routes() 返回 []surface.RouteInfo。

type Config struct {
    // Policy 与 (PolicySource+PolicyOptions) 二选一；后者让 server.New 一步建策略。
    Policy        *policy.Set
    PolicySource  policy.Source
    PolicyOptions policy.Options

    Services []Registration // 默认 API 面
    APIs     []APIConfig    // 可选：按 public/internal/partner 分前缀

    GRPCAddr   string
    HTTPAddr   string
    DisableGRPC bool // 只跑 HTTP
    DisableHTTP bool // 只跑 gRPC
    TLS        *tls.Config

    // 追加/覆盖 gRPC server 选项（凭证、keepalive 等）。
    GRPCOptions []grpc.ServerOption
    // 默认 8MiB；HTTP 侧 BodyLimit 同步使用同一上限。
    MaxRecvMsgSize int
    MaxSendMsgSize int
    // HTTP server 超时；零值用安全默认。
    HTTPReadHeaderTimeout time.Duration
    HTTPReadTimeout       time.Duration
    HTTPWriteTimeout      time.Duration
    HTTPIdleTimeout       time.Duration
    // gateway -> gRPC 的拨号配置（TLS、bufconn、target 重写）。
    Dial gateway.DialConfig

    // gateway 注入 client-ip 与 gRPC clientinfo 共用同一份信任集。
    TrustedProxies []string

    Authenticators authn.Chain
    AuthnOptions   authn.Options
    // Session/Cookie 认证必须配 CSRF；session.Authenticator.RequiresCSRF() 为
    // true 但这里为 nil → 启动失败。
    CSRF        *csrf.Config // nil = 未配置；session auth 会要求它
    AllowNoCSRF bool
    // 默认 false：存在非 anonymous 策略但没有 authenticator / authz Stage
    // 时启动失败。明确由网络层/网格认证兜底的项目可以设为 true。
    AllowNoAuthenticator bool
    AllowNoAuthz         bool
    // 默认 false：policy.Set 里每个 operation 都必须有对应注册；
    // 共享策略集给多个 server 的项目可以设为 true。
    AllowUnregisteredPolicies bool
    Decider              authz.Decider // 默认 RequirementDecider
    AuthzOptions         authz.Options
    Chain          *interceptor.Chain
    Mux            gateway.MuxOptions

    // 原生 HTTP 路由（次要逃生口）与全局中间件。
    ExtraRoutes    []ExtraRoute
    HTTPMiddleware []gateway.Middleware

    // 零值安全：默认开启健康检查；显式关闭才设为 true。
    DisableHealth bool
    // 可选：/readyz 依赖检查；nil = 只检查进程存活。
    Readiness func(ctx context.Context) error
    // 默认 false：逐请求 access log 由项目按需开启。
    AccessLog bool
    // 默认 false；生产按需开启。
    Reflection bool
    // 非 nil 时挂 GET /docs/openapi.json（多 API 用 APIConfig.Docs）。
    Docs fs.FS

    Logger          *slog.Logger
    ShutdownTimeout time.Duration
}

func New(ctx context.Context, cfg Config) (*Server, error)
func (s *Server) Run(ctx context.Context) error
func (s *Server) Shutdown(ctx context.Context) error
func (s *Server) Routes() []surface.RouteInfo
func (s *Server) Operations() []policy.Operation
```

`New` 做启动期断言（全部聚合，不挤牙膏）：

- `Policy` 与 `PolicySource` 必须二选一（同时提供 → 启动失败）；两者都为空时
  只有在「仅 ExtraRoute」场景才允许，使用空 Set。
- `policy.Set` 中每个 operation 都必须有对应注册（proto service 或 extra route）；
  共享策略集给多个 server 时用 `AllowUnregisteredPolicies` 放宽。
- 每个 Registration 的 `Descriptor` 与 `RegisterGRPC` 非 nil；`RegisterHTTP` 只有在
  该 service 没有任何 HTTP 暴露方法时才可以为 nil（纯 internal service）。
- 每个 gRPC 方法都有策略；同一 full name 的 gRPC 注册只执行一次（HTTP 可按 API 多次）。
- 每个 public/deprecated 方法在 proto 上都有 `google.api.http` 绑定（`Surface` 断言；
  注册函数是否真的挂上由生成代码与集成测试保证）。
- proto 路由之间、extra route 之间、proto 与 extra 之间无重复 `verb+path`。
- extra route handler 非 nil；`Public` 与 `Policy` 互斥，且至少设置一个。
- 多 API 的 Name 唯一、Prefix 合法且不互相遮蔽。
- service 的 `APISpec.api` 与注册到的 `APIConfig.Name` 不一致 → 启动失败
  （防止 internal service 被误挂到 public 前缀；确需覆盖时显式
  `Registration.AllowAPIMismatch=true`）。
- `EXPOSURE_INTERNAL` 的方法不得出现在任何 HTTP mux 的 `RegisterHTTP` 覆盖范围
  （以 `Surface` 为准；实际 handler 由集成测试兜底）。
- 若存在非 anonymous 策略但没有 authenticator → 启动失败（`AllowNoAuthenticator` 可放宽）。
- 若任一 Authenticator 实现 `RequiresCSRF() bool` 且返回 true，但 `CSRF` 为 nil
  → 启动失败（`AllowNoCSRF` 可放宽）。
- 若存在非 anonymous 策略但 chain 里没有 authz Stage → 启动失败
  （`AllowNoAuthz` 可放宽）；自定义 chain 最容易漏掉这一步。
- 若放行 streaming 且存在非 anonymous 流式方法，chain 必须有 stream authz；
  只有 unary authz 会导致流式方法绕过授权。
- chain 顺序合法；默认 chain 的 authn/authz 位置正确。
- 至少一个监听地址；`DisableGRPC`/`DisableHTTP` 不能同时为 true。
- 至少有一个 Service 或 ExtraRoute；只有 ExtraRoute 时必须是 HTTP-only 形态。
- `DisableHTTP=true` 时不能有 ExtraRoute/Docs/HTTPMiddleware；`DisableGRPC=true`
  时仍需要内部 bufconn 为 gateway 服务。
- `Docs` 路径存在；默认错误体/decider 可构造。

`Run` 启动 gRPC + HTTP，ctx 取消后优雅退出。HTTP 地址为空则只跑 gRPC。

### 5.17 `testkit`

```go
package testkit

func NewServer(t testing.TB, cfg server.Config) *Server
func (s *Server) GRPC() *grpc.ClientConn
func (s *Server) HTTP() *http.Client
func (s *Server) URL() string

func Principal(kind string, claims map[string][]string) *principal.Principal
func WithPrincipal(ctx context.Context, p *principal.Principal) context.Context
func BuildPolicy(t testing.TB, src policy.Source, opts policy.Options) *policy.Set

// 网络测试用：从固定测试头读取 principal，避免每个测试写一个 authenticator。
func StaticAuthenticator(p *principal.Principal) authn.Authenticator
func HeaderAuthenticator(header string) authn.Authenticator

// 直接给 gRPC/HTTP 请求注入测试凭证。
func WithTestCredential(ctx context.Context) context.Context
```

`NewServer` 用 bufconn 跑 gRPC、`httptest` 跑 HTTP，并自动 `t.Cleanup`。集成测试不再手写监听/拨号/关闭。`WithPrincipal` 只对进程内直调有效；走网络时用
`StaticAuthenticator`/`HeaderAuthenticator`。

### 5.18 从 proto Service 到 gRPC + grpc-gateway 的装配

**路由的唯一事实源仍然是 proto。** `google.api.http` 决定 HTTP 路径/verb，
`grpcapi.v1` 决定暴露面与策略。库不引入一套平行的「手写路由表」作为主模型；
它只负责把 proto Service 自动装成 gRPC server + grpc-gateway handler。

装配单元是 `server.Registration`（完整定义见 §5.16）：一个 proto Service 的
gRPC 注册 + HTTP 注册 + descriptor。便捷构造器：

```go
package server

type HTTPRegisterFunc func(context.Context, *runtime.ServeMux, grpc.ClientConnInterface) error

func NewRegistration(
    desc protoreflect.ServiceDescriptor,
    registerGRPC func(*grpc.Server),
    registerHTTP HTTPRegisterFunc,
) Registration
```

手写适配器（约 6 行）：

```go
func NewNoteServiceRegistration(impl NoteServiceServer) server.Registration {
    return server.NewRegistration(
        File_notes_proto.Services().ByName("NoteService"),
        func(s *grpc.Server) { RegisterNoteServiceServer(s, impl) },
        func(ctx context.Context, mux *runtime.ServeMux, conn grpc.ClientConnInterface) error {
            return RegisterNoteServiceHandlerClient(ctx, mux, NewNoteServiceClient(conn))
        },
    )
}
```

> **必须用 `RegisterXxxHandlerClient` + 回环连接，不要用 `RegisterXxxHandlerServer`。**
> 后者直接调用服务实现，绕过 gRPC 拦截器，authn/authz/validate 会全部失效。
> 回环多一跳，但保证 HTTP 与 gRPC 走同一条策略链。可以用 bufconn/unix socket
> 回环降低成本，但不要用「直连 handler」换性能。
>
> `RegisterHTTP` 约定为 `RegisterXxxHandlerClient` 形态。若项目只有
> `RegisterXxxHandlerFromEndpoint`，需要用适配器包一层；它会新建独立连接，
> 不共享 `server` 的 in-process conn，不推荐作为默认路径。
>
> 推荐提供可选 `protoc-gen-grpcapi` 生成这个 bundle。codegen 只消除 6 行样板，
> 不承载隐藏语义；没有它也能跑。

`server.New` 负责全部装配：

```go
srv, err := server.New(ctx, server.Config{
    Policy:   set,
    Services: []server.Registration{
        notesv1.NewNoteServiceRegistration(&impl{}),
    },
    GRPCAddr: ":9060",
    HTTPAddr: ":8080",
})
```

开发者写什么 / 库做什么：

| 开发者 | 库 |
|---|---|
| proto Service + `google.api.http` | 提取 `Surface` 与路由表 |
| `Registration`（6 行或 codegen） | gRPC 注册 + gateway 注册 |
| `policy.proto` 注解 | 策略收集 + fail-closed 断言 |
| `server.Config` | mux/dial/register/mount/中间件/生命周期 |

与手写 gateway 装配相比：

| 手写 | `server.New` |
|---|---|
| `runtime.NewServeMux` + N 个 option | 默认 mux |
| `grpc.NewClient` + credentials | `Dial` 默认/可覆盖 |
| 每个服务一个 `RegisterXxxHandlerClient` 闭包 | `Registration` |
| 自己 mount 到 `http.Server` | 自动 mount |
| 自己处理优雅退出 | `Run(ctx)` |
| 自己打印路由表 | `Routes()` + 启动日志 |
| 自己写启动断言 | `New` 内置 |

它内部做：

1. 从 `Services[].Descriptor` 构建 `surface.Surface`（HTTP 绑定来自 `google.api.http`）。
2. 创建 gRPC server，逐个 `RegisterGRPC`。
3. 创建 gateway `runtime.ServeMux`（默认错误体/header/marshaler）。
4. 拨号 gRPC：**默认 in-process bufconn**，不占端口、不走 loopback/TLS；
   需要网络回环时由 `Dial.Target` 覆盖。
5. 逐个 `RegisterHTTP` 到 mux。
6. 把 mux 挂到 HTTP handler 的对应前缀/API 面。
7. 套全局 HTTP middleware（recovery/requestid/accesslog + 项目追加）。
8. 启动断言：注册方法有策略、public 方法有 HTTP 绑定、HTTP 路径无重复/冲突。
9. 先 listen/serve gRPC，再 listen/serve HTTP；gRPC 启动失败必须 fail-fast，
   不能让 HTTP 先起来然后所有请求 502。启动后打印路由表。

> **客户端 IP**：in-process 连接没有 gRPC peer IP。gateway 必须用
> `runtime.WithMetadata` 从 `r.RemoteAddr`/可信代理链解析真实客户端地址，写入
> 受信任的 `x-grpcapi-client-ip` metadata；`clientinfo` 优先采信该键。
> 无 peer 时直接信客户端自带的 `X-Forwarded-For` 会被伪造。
>
> `server.Config.TrustedProxies` 同时供 gateway 注入与 gRPC `clientinfo` 使用，
> 两处共用同一套 CIDR 解析，避免一份信任集两处配置漂移。
>
> 实现上可以让同一个 `*grpc.Server` 同时 `Serve` 外部 listener 和内部 bufconn
> listener（grpc-go 支持多 listener）；拦截器对两条路径都生效。`DisableGRPC`
> 只关外部 listener，内部 bufconn 仍为 gateway 服务。

多 API / 前缀装配：

```go
type APIConfig struct {
    Name       string
    Prefix     string // 如 "/api"、"/internal"
    Services   []Registration
    Middleware []gateway.Middleware
    Mux        gateway.MuxOptions
    Docs       fs.FS // 可选：挂 /docs/<name>/openapi.json
}

type Config struct {
    Policy   *policy.Set
    Services []Registration // 默认面
    APIs     []APIConfig    // 可选：按面分前缀
    // ...
}
```

- 一个 gRPC server 承载全部 service（同进程）。
- 每个 API 面一个 gateway mux，挂在自己的前缀下。
- 最终路径 = `APIConfig.Prefix` + `Registration.Prefix` + `google.api.http` path；
  重复斜杠归一。
- 前缀挂载必须同时处理 `URL.Path` 与 `URL.RawPath`（转义路径），不能只改
  `Path`；否则含 `%2F` 等转义段的路径会错配。
- `server.New` 不修改调用方传入的 `*policy.Set`；extra route 的 operation 通过
  `set.WithOperations(...)` 生成合并后的不可变 Set。
- **同一个 Service 出现在多个 API 面时，gRPC 只注册一次**（按
  `Descriptor.FullName()` 去重），HTTP 可以注册到多个 mux/前缀。两个 Registration
  对同一 full name 提供不同的 `RegisterGRPC` → 启动失败。
- `APISpec.api` 决定 service 属于哪个面；`Registration.API` 为空时自动派生，
  非空时只用于校验/分组，不一致默认启动失败，确需覆盖时用 `AllowAPIMismatch`。
- `APIConfig` 只提供该面的前缀/mux/中间件/文档，不改变 service 的归属。
- 只有 `Registration.API` 而没有对应 `APIConfig` 时，该 API 面使用默认前缀（空）、
  默认 mux 与默认中间件，不会静默丢弃。
- `Server.Routes()` 返回从 `Surface` 派生的路由表（method/path/fullMethod/label/exposure/API）。
- 路由表启动时打印；`guard` 也消费同一份 `Surface`。

Tier 1 仍然可以逐件组装：

```go
mux, err := gateway.NewMux(gateway.MuxOptions{...})
conn, err := gateway.Dial(ctx, addr, gateway.DialConfig{})
err = gateway.Register(ctx, mux, conn,
    notesv1.NewNoteServiceHTTP,
    usersv1.NewUserServiceHTTP,
)
handler := gateway.Handler(gateway.HandlerOptions{
    Gateway: mux,
    Middleware: []gateway.Middleware{...},
})
```

`gateway.Register` 就是现有的 `RegisterFunc` 列表；`server.New` 只是把它做成了默认路径。

### 5.19 原生 HTTP 路由：次要逃生口

proto 路由是主模型。health、webhook、OAuth callback、静态文件等无法用
`google.api.http` 表达的路由，才用 `server.Config.ExtraRoutes` 挂载。

**范围限制（v3.0）**：ExtraRoute 只用于 health/webhook/static/OAuth callback。
业务 CRUD/查询必须走 proto；否则会出现第二套路由模型，策略、文档、SDK、矩阵
都会分叉。需要任意 handler 的项目使用 Tier 1 的 `gateway.NewHandler`，并自行
承担 guard 覆盖变弱的代价。

```go
type ExtraRoute struct {
    ID       string // 默认 "GET /path"；进入 policy.Set 的 operation ID
    Method   string
    Path     string
    Handler  http.Handler
    Policy   *policy.Policy
    Public   bool
    Exposure policy.Exposure
    Label    string
}

func GET(path string, h http.Handler) ExtraRoute
func POST(path string, h http.Handler) ExtraRoute
func PUT(path string, h http.Handler) ExtraRoute
func PATCH(path string, h http.Handler) ExtraRoute
func DELETE(path string, h http.Handler) ExtraRoute

func (r ExtraRoute) Public() ExtraRoute
func (r ExtraRoute) Authenticated() ExtraRoute
func (r ExtraRoute) Roles(roles ...string) ExtraRoute
func (r ExtraRoute) Permissions(perms ...string) ExtraRoute
func (r ExtraRoute) Scopes(scopes ...string) ExtraRoute
func (r ExtraRoute) Require(p policy.Policy) ExtraRoute

srv, err := server.New(ctx, server.Config{
    Policy:   set,
    Services: services,
    ExtraRoutes: []server.ExtraRoute{
        server.GET("/healthz", health).Public(),
        server.POST("/webhooks/stripe", stripe).Public(),
        server.GET("/admin/stats", stats).Roles("admin"),
    },
})
```

- `ExtraRoute` 挂载在 HTTP handler 顶层，不参与 API 前缀；health/webhook 通常如此。
- `ExtraRoute` 是 `Kind=HTTP` 的 operation，进入同一张 `policy.Set` 与 manifest。
- 冲突检测：extra route 与 proto route 同 `verb+path` → 启动失败（除非显式覆盖）。
- proto 路由的策略由 gRPC 拦截器执行；extra route 的策略由 HTTP 中间件执行。
- `server` 自动只给 extra route 套 authn/authz 中间件，**不会给 gateway 路由重复套**。
- 没有 extra route 的项目完全不需要了解这一层。

### 5.20 授权只在一处执行

- **proto 路由**：gateway 只做 HTTP → gRPC 转发；认证/授权/校验全部在 gRPC 拦截器链。
  不在 HTTP 层再包一层 authz，避免两次决策、两套错误体、两套审计。
- **原生 extra route**：没有 gRPC 后端，使用 `authn.HTTPMiddleware` +
  `authz.HTTPMiddleware`，共享同一个 `Chain`、`Decider`、`Principal`、`policy.Set`。
- 错误统一走 `gateway.ErrorEncoder`；gRPC 错误由 gateway 错误处理器写出，
  extra route 由同一 encoder 写出。
- 无效凭证在 public 路由上也 401（gRPC 与 extra route 语义一致）。

```go
package authn

type HTTPOptions struct {
    Options
    ErrorWriter ErrorWriter // 与 gateway.ErrorEncoder 共享，保证 401 错误体一致
}

func HTTPMiddleware(chain Chain, opts HTTPOptions) func(http.Handler) http.Handler

package authz

// extra route 的 operation 在注册时就已知，直接传入，避免运行时再查表。
func HTTPMiddleware(decider Decider, op policy.Operation, opts HTTPOptions) func(http.Handler) http.Handler

type OperationResolver func(*http.Request) (policy.Operation, bool)

// 动态路由（例如挂载第三方 router）才需要 resolver。
func HTTPMiddlewareFor(set *policy.Set, decider Decider, resolve OperationResolver, opts HTTPOptions) func(http.Handler) http.Handler

type HTTPOptions struct {
    ResourceResolver ResourceResolver
    ErrorWriter      ErrorWriter
    OnDecision       func(ctx context.Context, op policy.Operation, d Decision)
}
```

`server` 对每个 extra route 使用 `HTTPMiddleware(decider, route.Operation, opts)`；
proto 路由不经过它。`server` 用同一个 `ErrorEncoder` 构造 `ErrorWriter`，保证
extra route 的 401/403 与 gateway 错误体完全一致。

### 5.21 `server` 的开箱即用承诺

`server.New` 的零配置承诺只针对**本地开发与测试**；生产必须显式给地址/TLS。

最小输入（策略已构建）：

```go
server.New(ctx, server.Config{
    Policy:   set,
    Services: services,
})
```

或者让 `server.New` 顺带构建策略：

```go
server.New(ctx, server.Config{
    PolicySource:  policy.FromRegistry("notes.api.v1"),
    PolicyOptions: policy.Options{Registry: policy.DefaultRegistry()},
    Services:      services,
})
```

此时 `server.New` 会把 `Services` 的 full name 填进
`PolicyOptions.IncludeServices`，共享 package 里未注册的 service 不会被误报。
若调用方自己传了 `Policy`，则用 `AllowUnregisteredPolicies` 控制是否严格。

自动补齐：

| 项 | 默认 |
|---|---|
| gRPC 链 | recovery → requestid → clientinfo → authn → authz → validate |
| HTTP mux | 默认 ErrorEncoder + HeaderPolicy + 标准 JSON marshaler |
| HTTP 中间件 | recovery → requestid（access log / CORS / 限流按需追加；proto 路由不重复 authz） |
| 健康检查 | `GET /healthz` 存活；`GET /readyz` 调用 `Readiness`，失败返回 503 |
| 路由装配 | 从 proto Service 自动注册 gRPC + gateway；extra route 按需挂载 |
| 地址 | `127.0.0.1:9060` / `127.0.0.1:8080`（仅本地默认） |
| 启动断言 | 注册方法有策略、public 有 HTTP 绑定、路由无冲突 |
| 日志 | 启动时打印路由表与 policy manifest 摘要 |

显式关闭/替换：

```go
server.Config{
    DisableGRPC: true, // 只跑 HTTP（内部用 bufconn 连 gRPC）
    DisableHTTP: true, // 只跑 gRPC
    DisableHealth: true,
    Reflection:  true,
    Docs:        docsFS, // 挂 GET /docs/openapi.json
    Chain:       customChain,
    Mux:         customMux,
}
```

`Server.Routes()` 返回从 `Surface` + extra route 派生的路由表；启动日志打印
method、path、label、exposure，让「路由到底挂了什么」不再靠猜。

---

## 6. 特化能力矩阵

| 需求 | 扩展点 | 默认实现 | 说明 |
|---|---|---|---|
| 策略来源不同 | `policy.Provider` | `policy/protopolicy` | 旧 proto、配置中心、数据库、外部服务 |
| 项目命名策略 | `policy.Preset` | 无 | `tw.server` 等宏，构建期展开 |
| 新谓词 | `policy.Kind` | authenticated/claim/principal_kind/role/permission/scope | 租户、audience、mTLS、资源属性 |
| 外部策略引擎 | `authz.Decider` | `RequirementDecider` | OPA/Cerbos/Casbin/SpiceDB/自研 |
| 对象级授权 | `authz.ResourceResolver` + Kind/Decider | 无 | owner/tenant/relation |
| 认证方式 | `authn.Authenticator` | `authn/jwt`、`authn/session`、`authn/apikey` 参考实现 | mTLS/自研认证器 |
| 凭证提取 | `authn.Extractor` | `DefaultExtractor` | 自定义头/cookie/mTLS 组合 |
| 认证后增强 | `authn.Enricher` | `authn/admin`（合并 admin 角色） | 租户/组织/风控信息 |
| CSRF | `csrf` 中间件 | double-submit cookie + SameSite | 项目自定义 token/来源校验 |
| 流式授权粒度 | `MethodSpec.StreamAuth` | `OPEN`；按方法可设 `PER_MESSAGE` | 逐消息资源映射 |
| 限流 | `interceptor.Limiter` | 无（no-op） | 内存/Redis/网关限流 |
| 审计 | `interceptor.Auditor` | 无（no-op） | 落库/消息队列 |
| 用量计量 | `interceptor.Meter` | 无（no-op） | 计费/配额 |
| 校验器 | `interceptor.Validator` | protovalidate | 其他校验库 |
| 链顺序 | `interceptor.Stage` | 内置顺序常量 | recovery/metrics/custom |
| proto 路由装配 | `server.Registration` | `server.New` 自动装配 | gRPC 注册 + gateway 注册 + descriptor |
| 多 API / 前缀 | `server.APIConfig` | 单 API 面 | 按前缀/API 面拆 mux |
| 额外 HTTP 路由 | `server.ExtraRoute` | 无 | health/webhook/static 等逃生口 |
| HTTP 中间件 | `server.HTTPMiddleware` | recovery/requestid（accesslog/CORS 按需） | 全局/API 面作用域 |
| HTTP 认证/授权 | `authn.HTTPMiddleware` / `authz.HTTPMiddleware` | 仅 extra route 使用 | proto 路由由 gRPC 链授权 |
| 路由表 | `Server.Routes()` | 从 `Surface` 派生 | 启动日志/守卫/调试 |
| 传输层 | `gateway` 适配器（未来 Connect） | grpc-gateway | `policy/surface/guard` 不依赖传输 |
| 文档格式 | `guard.Loader` | OpenAPI v2（v3 loader 在 v3.1） | 自研文档、AsyncAPI |
| 错误体 | `gateway.ErrorEncoder` | JSON/proto | 项目契约 |
| Header | `gateway.HeaderPolicy` | 安全默认 | 项目专属头 |
| 日志/指标 | hooks | slog | OTel 适配器 |
| 策略热更新 | 自定义 `Decider`/`Set` 替换 | 不可变 Set | 原子指针或引擎内部处理 |

**判断是否该加 SPI 的标准**：至少有一个真实消费者，或者两个明确的实现路径。不要为「未来可能」加抽象。

---

## 7. 关键语义与安全

### 7.1 策略继承

```text
method.policy > service.default_policy > file.default_policy > 失败
method.exposure > service.default_exposure > file.default_exposure > 失败
method.label > preset > 自动派生
```

方法策略默认是**整体替换**，不是隐式合并。需要「在默认上再收紧」时显式设置
`inherit_default: true`，此时有效策略为：

```text
effective = AND(default_policy, method_policy)
```

`inherit_default` 与 `anonymous` 互斥；`anonymous` 只能作为整体替换出现。这样既
避免「以为收紧了，其实放宽了」的事故，也避免每个方法重复默认条件。

### 7.2 求值

- deny-overrides：`forbid` 优先。
- `any_of` 为空 = 无 OR 约束，不是 allow-all。
- `anonymous` 不要求 Principal；非 anonymous 且无 Principal → `Unauthenticated`。
- 求值错误 → `Internal`，绝不 fail-open。
- `Decision.Reason` 进审计日志，不下发客户端。

### 7.3 认证

- 无凭证 → 继续，由授权决定。
- 无效凭证 → 立即 `Unauthenticated`，public 方法也不例外。
- 多凭证 → 默认拒绝。
- public 方法 + 有效凭证 → 正常放行，Principal 可供审计使用。
- 认证成功后按序运行 `Enrichers`；admin store 故障 → `Unavailable`，不能降级成
  「没有 admin 角色」。admin 角色写入独立的 `admin_roles` claim，不混入普通 `roles`。
- **默认 in-process 连接没有 gRPC peer IP**。gateway 必须注入可信的
  `x-grpcapi-client-ip` metadata（从 `r.RemoteAddr` 或可信代理链解析），
  `clientinfo` 优先采信；否则只能退回 XFF，存在伪造风险。
- 若项目坚持网络回环（`Dial.InProcess=false`），gRPC peer 是 127.0.0.1/::1；
  `clientinfo` 必须把 gateway 地址加入 trusted proxies，否则所有客户端 IP 失真。
  `server` 默认信任 `127.0.0.1/32`、`::1/128`（可关/可覆盖）。

### 7.4 词表

- `Vocabulary` 按 domain 注册，不再只有 scope。
- `Requirement.Vocabulary` 缺省规则：普通 kind 用 kind 名；`claim` 用
  `params.name`（如 `claim:role`），避免所有 claim 共用一张词表。
- 注册了 domain → 值必须命中；未注册 → 自由值。
- `Kind.RequiresVocabulary` 为 true 且缺失 → 失败。
- 死值检测是可选 `Rule`，不是内置强制。
- `scope` 预设按资源部分校验词表（`notes:write` 校验 `notes`），不是整串精确匹配。

### 7.5 流式（v3.0 一等能力）

- server-streaming / client-streaming / bidi 全部支持。
- `DisableStreaming` 默认 false（零值 = 允许）；不需要流式的项目可显式关闭。
- 认证在 stream 建立时执行一次；`Principal` 放入 stream context。
- 授权默认在 stream 建立时执行（open-time）。逐方法可配置：
  - `STREAM_AUTH_MODE_OPEN`（默认）：建立时决策一次。
  - `STREAM_AUTH_MODE_PER_MESSAGE`：每条 `RecvMsg` 后重新决策；需要项目提供
    消息 → 资源映射；`Decider` 的 `Request` 是当前消息。
- 校验：
  - client-streaming / bidi：包装 `RecvMsg`，逐条校验。
  - server-streaming：只校验首个请求；响应消息由业务保证，不在拦截器校验。
- 审计/用量：stream 建立与结束各记一次；`PerMessage` 模式可选逐消息事件。
- **HTTP 暴露约束**：
  - client-streaming / bidi **不能**由 grpc-gateway 转码；`surface` 对
    `EXPOSURE_PUBLIC` 的这类方法启动报错，必须标 `EXPOSURE_INTERNAL`/`HIDDEN`。
  - server-streaming 可以用 grpc-gateway 的 `ForwardResponseStream` 暴露；
    生成器/handler 必须支持流式响应。
  - 流中错误可能发生在 HTTP 200 之后；客户端必须能处理「200 + 中途断流」。
- 拦截器包装器必须完整转发 `Context/RecvMsg/SendMsg/SetHeader/SetTrailer`。

### 7.6 错误码

| 场景 | gRPC code | HTTP |
|---|---|---|
| 无凭证/无效凭证 | Unauthenticated | 401 |
| 权限不足 | PermissionDenied | 403 |
| 运行时缺策略 | Internal | 500 |
| 求值错误 | Internal | 500 |
| 资源解析失败 | 项目指定，默认 Internal | 500 |
| 校验失败 | InvalidArgument | 400 |
| 限流 | ResourceExhausted + RetryInfo | 429 + Retry-After |

### 7.7 未知字段与 schema 演进

- 默认 Provider 拒绝扩展消息 unknown fields。
- `schema_version` 高于支持版本 → 失败。
- 新增策略字段必须可选、默认不改变授权结果。
- 策略 manifest 进 CI 产物，任何权限变化都可 diff。

### 7.8 对象级授权

- 方法级策略是默认；对象级授权是可选增强。
- `ResourceResolver` 只负责取资源，不做决策。
- 决策由 `Decider` 或自定义 `Kind` 完成。
- 资源解析失败不能 fail-open；默认 `Internal`，项目可映射为 `NotFound`。
- 请求字段在授权时可能尚未经过 validate；自定义 Kind 不得假设输入已校验。

### 7.9 多 API / 多租户

- `APISpec.api` 把文件分组到 public/internal/partner 等面。
- `Set.FilterAPI` / `Surface.OperationsByAPI` 支持按面构建 handler 与守卫。
- 租户是 Principal claim + 可选 `tenant` Kind；库不内置租户模型。
- 多 API 共享一个 gRPC server，HTTP 面可以分开监听。

### 7.10 常见授权模型映射

| 模型 | 表达方式 |
|---|---|
| 公开 | `anonymous: true` |
| 登录即可 | `authenticated: true` |
| RBAC | `roles: [...]` |
| 权限点 | `permissions: [...]` |
| OAuth scope | `scopes: [...]` |
| API key + scope | `principal_kind: ["api_key"]` + `scopes` |
| mTLS / 服务身份 | `principal_kind: ["service"]` 或自定义 Kind |
| ABAC | 自定义 Kind，读 `EvalContext.Request/Resource` |
| ReBAC / Zanzibar | `ResourceResolver` + `Decider`（SpiceDB 等） |
| 多租户 | `tenant` claim + 自定义 Kind |
| 拒绝规则 | `forbid` |
| 时间窗 / IP 白名单 | 自定义 Kind（读 Metadata/Peer/时间） |
| 外部 PDP | `Decider`（OPA/Cerbos/Casbin） |

这个模型不是任意布尔表达式：`require + any_of + forbid` 覆盖「正向要求 + 拒绝
覆盖」的绝大多数场景。需要任意逻辑、关系图或外部引擎时，走自定义 Kind 或
`Decider`，不要在 proto 里发明新的运算符。

### 7.11 认证/授权的执行位置

- **proto 路由**：`gateway` 只做 HTTP → gRPC 转发；`authn` / `authz` / `validate`
  全部在 gRPC 拦截器链。HTTP 层不重复 authz，避免两次决策。
- **原生 extra route**：没有 gRPC 后端，使用 `authn.HTTPMiddleware` +
  `authz.HTTPMiddleware`，共享同一个 `Chain`、`Decider`、`Principal`、`policy.Set`。
- 两类路由的 operation 都进入同一张 `policy.Set`；gRPC 的 ID 是
  `/pkg.Svc/Method`，extra route 的 ID 是 `VERB /path`。
- 错误统一走 `gateway.ErrorEncoder`，不出现「gRPC 错误体一种、HTTP 中间件另一种」。
- 无效凭证在 public 路由上也返回 401（与 gRPC 语义一致），除非显式配置忽略。

### 7.12 路由表与冲突

- **proto 路由**由 `Surface` 从 `google.api.http` 派生，不需要手写路由表。
- **extra route** 没有 `Policy` 且没有 `Public()` → 启动失败（fail-closed）。
- extra route 与 proto route 同 `verb+path` → 默认启动失败；显式覆盖才允许。
- 同一 `method+path` 重复注册 → 启动失败。
- 路由表启动时打印；`Server.Routes()` 可供测试/CLI 读取。
- 路由表是「装配结果的投影」，不是第二份路由定义；两份定义会漂移。

### 7.13 CORS / CSRF / 请求大小

- **CORS preflight 必须在 authn/authz 之前短路**；`OPTIONS` 不应要求凭证。
  `server` 的默认中间件顺序保证 CORS 在 authn/authz 之前（若启用）。
- **Cookie/session 认证需要 CSRF 防护**；`csrf` 包提供 double-submit cookie +
  SameSite + Origin/Referer 校验。`session.Authenticator` 标记 `RequiresCSRF`，
  `server.New` 发现未配置 CSRF 时启动失败（`AllowNoCSRF` 可放宽）。
- CSRF 只校验 unsafe method；`OPTIONS` 预检与 CORS 必须先短路。
- **HTTP BodyLimit 与 gRPC MaxRecvMsgSize 要匹配**；只限 HTTP 会被 gRPC 直连绕过，
  只限 gRPC 会让 gateway 先吃满内存。`server` 默认两边都设 8MiB，可覆盖。
- gRPC 直连与 gateway 回环都走同一套拦截器，但网络层限流/超时仍需分别在
  gRPC server 与 HTTP server 配置。
- **优雅退出顺序**：先停止接收 HTTP，排空在途 HTTP 请求，再 `GracefulStop`
  gRPC；超时后 `Stop`。反过来会让 gateway 的在途请求失去后端。

### 7.14 生命周期元数据

- `EXPOSURE_DEPRECATED` + `Deprecation{since,sunset,replacement}` 可驱动：
  - OpenAPI 的 `deprecated: true` 与 `x-deprecation` 扩展；
  - HTTP `Deprecation` / `Sunset` 响应头（可选中间件，默认不写）。
- `idempotent` 只是元数据，不自动实现幂等。需要幂等语义的项目使用可选
  `idempotency` 模块（key 提取 + 存储接口 + 响应重放），不要在 core 里硬编码。
- 这两类信息都进 policy manifest，CI 可以追踪 API 生命周期变化。

---

## 8. 守卫设计

### 8.1 为什么必须换成 `Surface`

v2 的守卫依赖：

- genproto 目录结构
- swagger 文件名与 proto 文件路径的对应
- `operationId` 的 `{Service}_{RPC}` 格式
- `ErrorResponse` 的定义名
- `x-<project>-access` 扩展名

这些都是**某一个生成管线的实现细节**。换成 `Surface` 后：

- 期望操作由 descriptor 的 `google.api.http` 生成。
- 文档只是 `Loader` 的一种实现。
- 匹配主键是 `verb+path`，不是文件名。
- `operationId` 只作为兜底与 service 推断。
- 错误体引用、标签、命名规则都是配置项。

### 8.2 匹配算法

```text
expected = for each documented operation in Surface:
    for each HTTPBinding:
        key = VERB + " " + normalize(path)
        value = {method, label, bindingIndex}

actual = for each DocumentOperation:
    key = VERB + " " + normalize(path)

for each actual:
    if expected[key] missing:
        if ignore(actual): continue
        if matchByOperationID: try fallback
        else: fail
    compare label
    compare error ref
    mark seen

for each expected:
    if !seen: fail("missing operation")
```

失败信息必须包含：

- full method
- verb + path
- 期望/实际 label
- 文档路径与 operationId

### 8.3 命名规则

`NamingRule` 支持：

- `SnakeCase`（默认，与 gateway marshaler 一致）
- `CamelCase`
- `Preserve`
- 自定义 `func(string) bool`

递归遍历 `properties` / `items` / `additionalProperties` / `allOf/oneOf/anyOf`，豁免 `@type`。

### 8.4 SDK 覆盖

```go
type SDKOptions struct {
    FieldName  func(protoreflect.ServiceDescriptor) string
    MethodName func(protoreflect.MethodDescriptor) string
}
```

默认仍是「去 Service + 首字母小写」，但项目可以覆盖。接口型/值型 wrapper 的反射逻辑保留。

### 8.5 文档/矩阵

`policy.Format(p)` 提供稳定的策略字符串，用于：

- 授权矩阵
- 日志/审计
- manifest diff
- 文档生成

`RenderMatrix` 提供默认列（Method / Exposure / Label / Policy），项目可自定义列与文案。

### 8.6 标签注入与生成管线

`guard.AssertDocuments` 比对的是文档里的 `x-grpcapi-policy`（或项目配置的键名）与
`Surface` 派生的 label。标签怎么进 OpenAPI 是生成管线的事，库提供三条路：

1. **项目 buf 插件/后处理**：从 `MethodSpec.label` 或 `policy.Format` 注入扩展。
   这是长期最干净的方式。
2. **`SkipMetadata: true`**：只做覆盖/命名/错误体检查，不检查 label。
   适合尚未接入标签注入的项目。
3. **`guard.InjectLabels`**（可选便利函数）：在构建期把 label 写进生成的 JSON，
   再由守卫读取。它会修改生成物，需和 `buf generate` 一起纳入 CI。

不建议让 guard 在测试期动态“修补”文档来通过断言；那会掩盖生成管线漂移。

### 8.7 路由表守卫

```go
func AssertRouteTable(t *testing.T, routes []surface.RouteInfo, o RouteTableOptions)
```

检查：

- 无重复 `method+path`。
- 所有 proto 路由都能在 `Surface` 中找到来源。
- 每个 extra route 要么显式 public，要么有策略。
- extra route 不覆盖 proto 路由（除非路由表里显式标记）。
- 路由 ID 与 `policy.Set` 中的 operation 一致。
- 若配置了 `Docs`，文档中的 proto 路由与路由表一致。

这样 fail-closed 覆盖「proto 路由 + health/webhook/static 等少量手写路由」，但主模型
仍然是 proto。

---

## 9. 架构取舍

### 9.1 糖 vs. 纯

固定糖字段（roles/permissions/scopes/authenticated）会重新引入几个传统维度。但它们是**脱糖**，不是运行时特例：

- 核心只认 `Requirement`。
- 糖只影响作者体验。
- 项目可以覆盖 kind 名/claim 名。
- manifest 永远输出脱糖后的树。

这是「方便 + 通用」的关键折中：**90% 的方法用糖，10% 的复杂策略用通用树。**

### 9.2 Preset vs. DSL

不做字符串 DSL。Preset 是 Go 函数，不是解释器：

- 没有语法/转义/解析器。
- 参数校验在项目代码里。
- 展开结果可 dump、可 diff。
- 缺点：参数是 `map[string]string`，复杂参数不适合；复杂逻辑请用 Provider/Decider。

### 9.3 Provider vs. 可 grep

Provider 让策略来源可插拔，但也让「策略在哪」变得不直观。缓解：

- 默认 Provider 覆盖 90% 项目。
- `policy manifest` 输出进 CI，任何权限变化都可 review。
- 自定义 Provider 必须在文档中声明来源。
- 启动日志打印策略来源与 manifest 摘要。

### 9.4 默认 vs. 安全

方便不能以 fail-open 为代价：

- 默认必须显式声明 anonymous。
- 默认拒绝 unknown fields / unknown kind / unknown preset。
- 默认无效凭证不降级。
- 默认错误脱敏。
- 默认 authorization header 不放行。
- 默认流式不授权 per-message（需显式开启）。

### 9.5 核心 vs. 模块

核心只保留：

- `policy` 类型/构建/校验
- `surface` IR
- `authz` 求值与拦截器
- `interceptor` 链
- `gateway` grpc-gateway 适配
- `guard` 文档/一致性

可选模块：

- `policy/scope`、`policy/expr`
- `authn/jwt`、`authn/apikey`、`authn/session`、`authn/mtls`
- `ratelimit`、`audit`、`observability/otel`
- `decider/opa`、`decider/cerbos`、`decider/casbin`、`decider/spicedb`
- `transport/connect`

重依赖（OPA/SpiceDB/Connect）建议拆独立 module 或独立 repo，只通过 SPI 连接；轻量模块可留在主 module。

### 9.6 与现有生态的关系

| 系统 | 模型 | 优势 | 局限 | 我们的关系 |
|---|---|---|---|---|
| OPA/Rego | 外部策略引擎 | 极其通用 | 独立语言/进程 | 通过 `Decider` 接入 |
| Cerbos | YAML 策略 PDP | RBAC/ABAC、derived roles | 外部 PDP，非 descriptor-first | 通过 `Decider` 接入 |
| Casbin | model/config | 简单 RBAC/ABAC | 运行时配置，类型弱 | 通过 `Decider`/Kind 接入 |
| SpiceDB | ReBAC/Zanzibar | 对象级关系 | 外部服务、schema | 通过 `ResourceResolver`/`Decider` 接入 |
| ConnectRPC | 传输 | 现代 HTTP/gRPC | 不是授权模型 | 未来 `transport` 适配 |
| grpc-gateway | 传输 | 成熟 REST 映射 | openapiv2 细节多 | 当前 `gateway` 适配 |
| protovalidate | 校验 | proto-first CEL | 不是授权 | `Validator` 适配 |
| Kubernetes RBAC | role/verb/resource | 简单直观 | namespace/verb 模型固定 | 可用 Requirement 表达 |
| Google AIP | API 设计 | resource-oriented | 不是授权库 | 影响 `Surface`/`Exposure` |

结论：**不要重造策略引擎；库的独特价值是 descriptor-first 的 IR、fail-closed 装配和一致性守卫。**

grpc-gateway 的版本耦合点（升级必须跑集成测试）：

- `authorization` 的自动 metadata 行为（双写 401 的来源）。
- `JSONPb` 对非 proto body 的序列化行为。
- `RegisterXxxHandlerServer` 的拦截器绕过语义（本库禁用）。
- `ServeMux` 的前缀/转义路径/尾斜杠行为。
- `WithMetadata` 与 incoming header matcher 的执行顺序。

建议 CI 固定一个 grpc-gateway minor，并在升级 PR 里跑完整的 HTTP 集成矩阵。

### 9.7 明确否决的方案

- **只保留 `AccessLevel` 枚举，加更多档位**：任何固定枚举都会在某天遇到「不属于这五档」的项目；最终变成枚举 + 大量例外字段。否决。
- **字符串策略 DSL**（如 `role:admin | scope:notes:write`）：作者方便，但解析、转义、错误定位、工具链、跨语言一致性成本高；preset + 糖已覆盖 90% 场景。否决作为核心，保留为可选实验。
- **把 OPA/Cerbos 内嵌为唯一引擎**：会把库变成某个引擎的 SDK，并引入重依赖；通过 `Decider` 接入更合适。否决。
- **ConnectRPC 优先/唯一传输**：torchwood 的 REST 契约在 grpc-gateway 上，且传输选择应独立于策略/守卫；v3 保持适配器边界。否决在 v3 切换。
- **代码生成优先**：手写 Registration 只有 6 行，codegen 会增加构建链复杂度；等手写模式稳定后再做可选插件。否决 v3 必需 codegen。
- **全功能框架**（自带 DI、配置、生命周期、插件系统）：与「库」定位冲突，也会让 Tier 1/2 用户失去控制权。否决；只提供可选 `server` facade。
- **运行时动态修补 OpenAPI 文档来通过守卫**：会掩盖生成管线漂移；守卫只读，标签由生成管线负责。否决在 guard 内自动修补。

### 9.8 路由装配：为什么以 gateway 装配为主，而不是另造路由框架

- **路由定义在 proto**：`google.api.http` 是唯一事实源；库不引入第二套手写路由表，
  否则两份定义必然漂移。
- **装配单元是 Service**：`Registration` 把一个 proto Service 的 gRPC 注册、
  gateway 注册和 descriptor 绑在一起；`server.New` 负责 mux/dial/register/mount。
- **不重造路由匹配**：具体 HTTP 匹配仍由 grpc-gateway（以及标准库 `ServeMux`）完成。
- **原生路由是逃生口**：health/webhook/static 用 `ExtraRoute` 挂载，不参与主模型。
- **可替换**：Tier 1 可以自己组 mux/dial/register；Tier 2 可以换传输适配器。
  库不把用户锁死在 `server.New`。

这也是「通用 + 特化」的体现：默认路径极短，偏离默认时仍能逐件控制。

### 9.9 开箱即用的边界

`server.New` 的零配置承诺只覆盖本地开发/测试：

- 生产必须显式地址、TLS、CORS、日志级别。
- 反射默认关闭；健康检查默认开启。
- 默认错误体是安全的通用 JSON；项目应替换成自己的契约。
- 默认不启用 pprof/metrics/pprof 类端点。
- 默认不假设任何认证方式；没有 authenticator 时 protected 方法返回 401。

「开箱即用」不等于「生产零配置」。它意味着：**从零到第一个可运行请求不需要读 20 页文档**。

---

## 10. 参考架构

### 10.1 小内部 API

- proto：`authenticated` + `roles` 糖。
- Go：`server.New` + 默认 registry/chain。
- 认证：一个 JWT 或内网 mTLS 认证器。
- 守卫：`guard.Suite` 只跑 policy + naming。
- 目标：20~30 行接入，不引入 gateway 以外的依赖。

### 10.2 产品 API

- proto：public / authenticated / permission / scope 混合。
- Go：Tier 1 组合，JWT + session + API key 认证器。
- 授权：`RequirementDecider` + 少量自定义 Kind。
- 守卫：OpenAPI v2 策略/命名/错误体 + SDK 覆盖 + 授权矩阵。
- 错误体：项目自定义 `ErrorEncoder`。
- 目标：完整的对外契约与 CI 一致性。

### 10.3 平台 / 多 API

- proto：`APISpec.api` 分 public/internal/partner；多租户 claim。
- 策略来源：自定义 `Provider`（配置中心/数据库）+ preset。
- 授权：`Decider` 路由到 Cerbos/SpiceDB；`ResourceResolver` 取对象。
- 传输：gRPC + 多个 HTTP mux；未来 Connect。
- 守卫：每个 API 面独立 `guard.Suite`；manifest diff 进 CI。
- 目标：特化能力全开，但核心包不变。

### 10.4 proto Service 为主 + 少量 extra route 的产品 API

典型需求：业务路由全部由 proto 定义；只有 health、Stripe webhook、OAuth callback
这类无法用 `google.api.http` 表达的路由才手写。

```go
srv, err := server.New(ctx, server.Config{
    Policy: set,
    Services: []server.Registration{
        notesv1.NewNoteServiceRegistration(&impl{}),
        usersv1.NewUserServiceRegistration(&userImpl{}),
    },

    // 次要逃生口：不参与主路由模型。
    ExtraRoutes: []server.ExtraRoute{
        server.GET("/healthz", health).Public(),
        server.GET("/readyz", ready).Public(),
        server.POST("/webhooks/stripe", stripeWebhook).Public(),
        server.GET("/oauth/callback", oauthCallback).Public(),
        server.GET("/admin/stats", stats).Roles("admin"),
    },

    Docs: docsFS,
    HTTPMiddleware: []gateway.Middleware{
        gateway.CORS(gateway.CORSOptions{AllowOrigins: allowedOrigins}),
        gateway.BodyLimit(1 << 20),
    },
})
```

- proto 路由由 `Services` 自动注册 gRPC + gateway，路径来自 `google.api.http`。
- extra route 是 `Kind=HTTP` 的 operation，进入 manifest 与授权矩阵。
- proto 路由的 authz 在 gRPC 链执行；extra route 用 HTTP authz middleware。
- 启动时打印完整路由表（proto + extra），冲突/漏策略立即报错。
- 没有 extra route 的项目只写 `Policy + Services` 即可。

---

## 11. 迁移与落地

### 11.0 v3.0 范围冻结

> 实现状态（2026-10-20）：`principal`、`policy`、`policy/scope`、`policy/protopolicy`、
> 新 `authz`、`authn` SPI + JWT/Session/API key/Admin + `csrf`、`interceptor.Stage`
> （unary+stream）、`surface`、`server.New`（in-process gateway、多 API、健康检查、
> 路由表）、example、`protoc-gen-grpcapi`、gateway v3
> （ErrorEncoder/HeaderPolicy/Marshaler）、guard v3
> （Document/OpenAPI v2+v3/Suite/SDK 覆盖）、`testkit` 已落地。
> 剩余：torchwood 迁移（见 MIGRATION.md）、Connect 适配器（不排期）。

**v3.0 必须交付：**

- `principal` + `policy` 核心（糖、Provider、Preset、Kind、manifest）
- `authn` SPI + JWT/Session/API key/Admin 参考实现 + CSRF
- `authz` 求值 + gRPC 拦截器 + HTTP middleware
- unary + server/client/bidi streaming；open-time / per-message 授权
- `interceptor.Stage` 链 + recovery/requestid/clientinfo/validate
- `gateway`（openapiv2 生态）：ErrorEncoder/HeaderPolicy/Dial/Handler
- `server.New`：proto Service 自动装配 gRPC + gateway + 多 API/前缀
- `protoc-gen-grpcapi`：Registration bundle（非必需路径）
- `surface` + `guard`（OpenAPI v2）+ 路由表/策略/命名/矩阵守卫
- Tier 0/1/2 示例、torchwood legacy Provider、CI 矩阵

> 迁移期实现说明：v3.0 落地初期仍可能保留旧 `genproto` 子 module，以让旧
> `authz`/example/testdata 继续编译；旧包删除后统一切到 `gen/` 单 module。
> 这是实施顺序，不是最终架构。

**v3.0 明确不做：**

- OpenAPI v3 loader（v3.1）
- Connect/HTTP-only 传输适配器
- 每个 API 面独立 gRPC server/端口
- 运行时加载 manifest 作为策略源
- 任意业务 native HTTP 路由（只允许 health/webhook/static/OAuth）
- pprof/metrics/OTel 默认端点（只留 hook）

### 11.1 阶段

| 阶段 | 内容 | 相对工作量 |
|---|---|---|
| M1 | `principal` + `policy` + `policy/protopolicy` + `policy/scope` + manifest | L |
| M2 | `authn` SPI + `authz` + `Decider` + `ResourceResolver` | M |
| M2.5 | `authn/jwt`、`authn/session`（含 CSRF）、`authn/apikey`、`authn/admin` 参考实现 | L |
| M3 | `interceptor.Stage` + **server/client/bidi streaming** + recovery/requestid | L |
| M4 | `gateway` ErrorEncoder/HeaderPolicy/Dial/Handler + **多 API/前缀** | M |
| M4.5 | `server` Service 装配 + extra route + 路由表/冲突检测；`protoc-gen-grpcapi` | L |
| M5 | `surface` + `guard` + `Suite` + OpenAPI v2（v3 可后置）+ 路由守卫 | L |
| M6 | 新 proto、单 module、Tier 0/1/2 示例、README | M |
| M7 | torchwood 迁移（legacy Provider 零 proto 改动）+ streaming 回归 | L |
| M8 | testkit、fuzz、benchmark、CI 矩阵 | S |

### 11.2 旧 → 新映射

| v2 | v3 |
|---|---|
| `service_auth.default_access` | `service.default_policy` |
| `method_auth.access` | `method.policy` |
| `ACCESS_LEVEL_PUBLIC` | `policy { anonymous: true }` |
| `ACCESS_LEVEL_END_USER` | `policy { authenticated: true }` 或 `principal_kind:["user"]` |
| `ACCESS_LEVEL_SERVER` + `admin_roles` + `api_key_scope` | `policy { any_of: [{roles:[...]}, {scopes:[...]}] }` 或 preset |
| `ACCESS_LEVEL_PERMISSION` + `permissions` | `policy { permissions: [...] }` |
| `ACCESS_LEVEL_SYSTEM` | 项目自定义 kind 或删除 |
| `api_key_scope {resource, op}` | `{kind:"scope", values:["resource:op"]}` 或 `policy/scope`（旧 `resource.op` 也接受） |
| `authz.Build` | `policy.Build` |
| `authz.PolicySet` | `policy.Set` |
| `authz.ScopeSet` | `policy/scope` |
| `interceptor.ChainItem{Slot,...}` | `interceptor.Stage{Name,Order,...}` |
| `gateway.ErrorBodyBuilder` | `gateway.ErrorEncoder` |
| `guard.SwaggerAccessMatches` | `guard.AssertDocuments` + `OpenAPIv2` |
| `guard.SwaggerSnakeCaseProperties` | `guard.AssertJSONNaming` |
| `guard.SwaggerNoDefinition` | `guard.AssertNoSchema` |
| `guard.AssertMethodCount` | `guard.AssertMethodCount(surface,...)` |
| 双 module + replace | 单 module + `gen/` |

### 11.3 torchwood 两条路

**A. 零 proto 改动（推荐先做）**

- 旧 `authz.proto` 已从 grpcapi 删除；torchwood 在自己的 repo 保留一份
  legacy proto + 生成代码，`legacyProvider` 读它。
- torchwood 实现 `legacyProvider`，读旧 `method_auth/service_auth`。
- 旧五档 + `api_key_scope` + `admin_roles` 在 provider 内展开为 `policy.Policy`：
  - `PUBLIC` → `anonymous`。
  - `END_USER` → `principal_kind: ["user"]`（不要只用 `authenticated`，否则
    admin/service 身份会混入）。
  - `SERVER` → `any_of: [admin_roles, scope]`；`admin_roles` 读 `admin_roles` claim，
    scope 用 `policy/scope` 的 resource:op 语义（兼容旧 resource.op）。
  - `PERMISSION` → `permission` kind，`MATCH_ALL`。
  - `SYSTEM` → 项目自定义 kind 或删除。
- streaming 方法必须在 provider 里保留 `StreamAuth`；torchwood 的旧实现如果只有
  unary 拦截器，迁移到 v3 后要补 stream 测试（三种类型）。
- admin 角色来源两者都有：JWT/session claims + admin store，合并到 `admin_roles`；
  不要合并进普通 `roles`。
- 库不感知旧模型；torchwood 可以先上线，再逐步迁移 proto。

**B. 一次性 codemod**

- 旧注解机械替换为 `preset: "tw.*"` + `preset_args`。
- preset 定义在 torchwood 代码里。
- proto 更干净，但需要改约 34 个文件。

建议先 A 再 B；A 的风险最小，且验证 v3 的 Provider 抽象是否真的够用。

迁移等价性证明：用旧版 `BuildMethodPolicies` 的输出生成 golden manifest，与
`legacyProvider` 构建的 v3 manifest 逐方法比对（归一化 enum/字符串形态）。
任何 access/scope/role 变化都必须显式 review，不能靠测试全绿蒙混过关。

### 11.4 验收标准

- [ ] Tier 0 示例 ≤ 30 行，跑通 gRPC + HTTP；HTTP 路由全部来自 proto。
- [ ] Tier 1 示例逐包组合，所有默认值可替换。
- [ ] Tier 2 示例实现 Provider + Preset + Decider + ResourceResolver。
- [ ] core/proto/example 不出现 torchwood 术语。
- [ ] 未知 kind/preset/字段/schema version 全部启动失败。
- [ ] unary + server/client/bidi stream 的 authn/authz/validate 均可用；
      open-time 与 per-message 两种授权模式有测试。
- [ ] client/bidi 流式方法标 `EXPOSURE_PUBLIC` 时启动失败（grpc-gateway 不能转码）。
- [ ] JWT / Session / API key / Admin 四个参考实现可用；session 必配 CSRF。
- [ ] gateway 支持非 proto 错误体；`NewMux` 不 panic。
- [ ] `server.New` 零配置（Policy + Services）能自动完成 mux/dial/register/mount。
- [ ] 多 API 前缀装配可用；同一 service 可挂多个 API 面；proto 路由无重复、
      public 方法有 HTTP 绑定。
- [ ] `protoc-gen-grpcapi` 能生成 Registration bundle；手写 Registration 仍可用。
- [ ] extra route 只有显式 Public 或有策略；与 proto 路由冲突时启动失败。
- [ ] proto 路由的 authz 只在 gRPC 链执行一次，HTTP 层不重复。
- [ ] `Server.Routes()` 输出稳定路由表，启动日志可见。
- [ ] guard 用 `fstest.MapFS` 即可测试，OpenAPI v2 完整支持；v3 loader 接口预留。
- [ ] 单 Go module，`go test -race ./...` 与 `buf generate` 零漂移。
- [ ] `policy manifest` 可输出并在 CI diff。
- [ ] 两个示例工程（public / internal）通过同一套守卫。

---

## 12. 风险清单

1. **抽象过多**：Provider/Preset/Kind/Decider 四层容易让新用户迷路。缓解：三层文档 + Tier 0 默认路径 + 每层只暴露一个入口。
2. **Preset 变成隐藏 DSL**：参数是字符串，语义在项目代码。缓解：manifest 输出、参数校验、禁止复杂 preset。
3. **Provider 让策略不可见**：缓解：默认 Provider 覆盖多数场景，CI manifest diff，启动日志。
4. **糖字段固化维度**：缓解：糖只脱糖，核心仍是 Requirement；项目可覆盖 kind/claim 名。
5. **对象级授权性能**：每次请求查资源/调外部引擎。缓解：默认关闭，项目可在 Resolver/Decider 内缓存。
6. **流式语义误解**：默认 open 时授权，且 client/bidi 不能走 grpc-gateway。
   缓解：`StreamAuthMode` 按方法显式；`surface` 对非法 HTTP 暴露启动报错；
   文档写明「stream 中错误可能发生在 HTTP 200 之后」。
7. **守卫路径匹配差异**：不同生成器 path 规范化不同。缓解：`operationId` 兜底、`Ignore` 规则、失败带原始操作。
8. **模块生态膨胀**：可选模块太多会拖垮维护。缓解：核心只保留机制；重依赖独立 module/repo；每个模块必须有真实消费者。
9. **安全边界模糊**：授权在 validate 之前。缓解：文档明确「授权不得假设输入已校验」；资源解析必须健壮。
10. **迁移成本**：torchwood 34 个 proto。缓解：legacy Provider 零改动接入。
11. **路由两份定义**：proto 与手写路由表并行必然漂移。缓解：主模型只认 proto；
    extra route 仅限 health/webhook/static；路由表只是装配投影，不是第二个来源。
12. **gateway 注册样板**：每个服务 6 行 adapter 仍可能烦。缓解：`server.New` 自动
    mux/dial/register；可选 codegen 生成 Registration；错误信息明确。
13. **HTTP/gRPC 双重授权**：proto 路由在 HTTP 层再包 authz。缓解：明确只在 gRPC 链
    授权；`server` 只给 extra route 套 HTTP authz middleware。

---

## 13. 最终建议

建议按两个验证闭环推进，而不是先铺开所有 SPI：

**闭环 A：方便**

- 做 `policy` 核心 + 糖 + `server.New`（Service 装配：gRPC + gateway 自动注册/挂载）。
- 验收：新项目 20~30 行、proto 里写好 `google.api.http`，就能跑通 gRPC + HTTP。
- 关键点：**HTTP 路由不手写**，全部从 proto Service 派生。

**闭环 B：通用 + 特化**

- 做 `Provider` + `Preset` + `RequirementKind` + `Decider`。
- 验收：torchwood 用约 50 行 `legacyProvider` 零 proto 改动接入，五档语义在项目侧展开。
- 关键点：库不出现 torchwood 的类型，但能完整承载它的模型。

两个闭环共用同一套 `policy.Set` / `authz.Decider` / `surface.Surface` / `guard`；
这才说明「方便」「通用」「特化」不是三套实现。

v3.0 在这个地基上再交付四块「开箱即用」能力：JWT/Session/API key/Admin 参考实现、
三种 streaming、多 API 前缀、`protoc-gen-grpcapi`。  
OPA/Cerbos/SpiceDB、Connect、OpenAPI v3、审计/限流实现仍可后置。

**先保证主路径极短，再保证逃生口足够；不要把「通用」做成「所有能力一次到位」。**

---

## 14. 深度复查：还需要补充和修正的点

这一节是第二轮对抗式复查的结果。标注「已修正」的已经写进上文；标注「待决策」
的需要项目拍板。

优先级：

| 优先级 | 项 |
|---|---|
| P0（安全/正确性） | 1 `HandlerServer`、2 多 API 去重、3 HTTP authz 签名、13 漏 authz、14 stream authz |
| P1（会导致误用/漂移） | 4 前缀、5 client IP、6 CORS/CSRF、7 启动断言、8 策略校验、9 错误边界、10 access log、11 零值、12 in-process、15 策略漂移、16 PolicySource |
| P2（可维护性） | 17 认证后端错误、18 guard 依赖、以及 14.2 的补充项 |

### 14.1 必须修正（影响正确性）

1. **`RegisterXxxHandlerServer` 会绕过 gRPC 拦截器**（已修正 §5.18）
   - 它直接调用实现，authn/authz/validate 全部不执行。
   - 必须用 `RegisterXxxHandlerClient` + 回环连接；可以用 bufconn/unix socket
     降低成本，但不能用「直连 handler」换性能。
   - 验收：HTTP 请求被 gRPC authz 拒绝时，必须返回 403/401，而不是穿透。

2. **同一 Service 出现在多个 API 面**（已修正 §5.18）
   - gRPC 注册只能一次，HTTP 可以按 API/前缀多次。
   - `server.New` 按 `Descriptor.FullName()` 去重 gRPC 注册；同一 full name
     对应不同 `RegisterGRPC` 函数 → 启动失败。

3. **HTTP authz 的 operation 查找**（已修正 §5.20）
   - extra route 的 operation 在注册时已知，直接传给中间件；不要在每个请求里
     再按 path 查表。

4. **部署前缀 vs OpenAPI 路径**（已修正 §5.14）
   - proto/OpenAPI 路径通常不带部署前缀；`APIConfig.Prefix` 是运行时挂载前缀。
   - `guard.MatchOptions.Prefix` 只用于匹配，不修改文档。
   - 多 API 需要独立文档时，用 `APIConfig.Docs`，不要把所有 API 塞进一份 doc。

5. **gateway 回环 IP**（已修正 §7.3）
   - gRPC peer 是 127.0.0.1/::1；不信任 gateway 地址会导致所有客户端 IP 失真，
     IP 限流与审计失效。
   - `server` 默认信任回环地址，可显式关闭/覆盖。

6. **CORS preflight 与 CSRF**（已补充 §7.13）
   - CORS 必须在 authn/authz 前短路 `OPTIONS`。
   - Cookie/session 认证需要 CSRF，库不默认实现；必须显式加中间件或采用
     SameSite + 自定义头校验。

7. **启动断言不能只查 descriptor**（已补 §5.16）
   - 还要查：重复 gRPC full name、重复 HTTP verb+path、extra route handler 为 nil、
     API 前缀互相遮蔽、protected 策略但没有 authenticator。
   - 这些是「配置错误」，不是「运行时错误」，必须启动即红。

8. **策略校验还有空洞**（已补 §5.6 / §7.4）
   - `any_of` 空组（恒真）。
   - `authenticated` 带 values/params。
   - 值型 kind values 为空。
   - `claim` 缺少 `params.name`。
   - `claim` 词表 domain 应默认用 claim 名。
   - 同一 kind 重复注册。

9. **错误编码边界**（已补 §5.12）
   - `Status==0`、`Body==nil`、`Encoder` 自身报错、`Headers` 覆盖、
     `Content-Type` 默认值，都要有确定行为。

10. **默认 access log**（已修正 §5.21）
    - 逐请求访问日志默认关闭；启动路由表默认打印。
    - 需要访问日志的项目显式开启，避免生产默认泄漏路径/租户信息。

11. **布尔配置的零值歧义**（已修正 §0.4 / §5.14 / §5.16）
    - `Health bool`、`RequireMetadata bool`、`RetryAfter bool`、
      `MatchByOperationID bool`、`RejectUnknownFields bool` 这类字段无法区分
      「未设置」与「显式 false」。
    - 改为 `DisableHealth`、`SkipMetadata`、`DisableRetryAfter`、
      `DisableOperationIDFallback`、`AllowUnknownFields` 等零值安全命名。
    - 这条规则适用于所有 `Options`/`Config`：零值必须是安全默认。

12. **gateway 连接默认应为 in-process**（已修正 §5.12 / §5.18 / §7.3）
    - 网络回环会引入端口占用、loopback TLS、peer IP 失真、防火墙策略等问题。
    - 默认用 bufconn/进程内连接；gateway 与 gRPC 之间不再走真实网络。
    - in-process 没有 peer IP，必须由 gateway 注入可信 `x-grpcapi-client-ip`，
      `clientinfo` 优先采信，不能直接信客户端 XFF。
    - 该内部头必须在入站 header matcher 的 Deny 列表里，防止客户端伪造。

13. **自定义 chain 可能漏掉 authz**（已修正 §5.11 / §5.16）
    - 项目替换 `Chain` 时最容易只装 recovery/validate，忘了 authz，导致策略形同虚设。
    - `server.New` 检查 chain 是否包含 authz Stage；有非 anonymous 策略却没有 → 启动失败。
    - 同理检查 authenticator；确需网络层兜底时显式 `AllowNoAuthz` /
      `AllowNoAuthenticator`。

14. **stream 可能只有 unary authz / 非法 HTTP 暴露**（已修正 §5.11 / §5.13 / §5.16 / §7.5）
    - `Chain.Unary()` 和 `Chain.Stream()` 是分开的；只实现 unary 的 authz Stage
      会让流式方法绕过授权。
    - `server.New` 检查 `HasStream("authz")`；放行 streaming 且存在非 anonymous
      流式方法时必须存在。
    - stream 包装器必须转发 Context/RecvMsg/SendMsg/Header/Trailer，不能只包 Context。
    - client-streaming / bidi **不能**走 grpc-gateway；`EXPOSURE_PUBLIC` 必须启动失败。

15. **策略集与注册面可能漂移**（已修正 §5.16）
    - 策略里有方法、服务没注册；或服务注册了、策略没有。两边都要查。
    - 默认 `AllowUnregisteredPolicies=false`：策略集中的每个 operation 必须有注册。
    - 共享策略集给多个 server 时显式放宽，避免误报。

16. **`PolicySource` 共享 package 的误报**（已修正 §5.6 / §5.21）
    - `policy.FromRegistry("pkg")` 可能包含本 server 未注册的 service。
    - `server.New` 构建策略时自动填 `IncludeServices`，只收集已注册 service；
      调用方显式传 `Policy` 时用 `AllowUnregisteredPolicies` 控制严格度。

17. **认证后端故障不能伪装成 401**（已修正 §5.10）
    - JWKS 拉取失败、session DB 不可用应返回 `Unavailable`/`Internal`，不是
      `Unauthenticated`；否则客户端会反复重试错误凭证。
    - 认证器错误如果是显式 gRPC status，原样透传；否则按 `Unauthenticated`
      处理并记录原始错误。

18. **`guard` 不应依赖 `server` facade**（已修正 §5.13 / §8.7）
    - `RouteInfo` 放在 `surface` 包；`guard.AssertRouteTable` 只依赖 `surface`。
    - 否则 test-only 的 guard 会把 gateway/grpc/server 全部拖进测试依赖。 

### 14.2 重要补充（影响可用性）

1. **codegen 的定位**
   - 1~3 个 service 手写 `Registration` 完全可接受。
   - 10+ service 或频繁增删 service 时，建议 `protoc-gen-grpcapi` 生成 bundle。
   - codegen 只生成注册样板与可选的 scope/permission 常量，不生成策略逻辑。

2. **多 API 文档**
   - `server.APIConfig.Docs fs.FS`；`guard.Suite` 每个 API 跑一次。
   - `/docs/<api>/openapi.json` 比单个 `/docs/openapi.json` 更清晰。

3. **manifest 稳定性**
   - `policy.Format` 和 `Manifest` 必须有固定排序（kind、vocabulary、values、
     map keys）；否则 CI diff 全是噪音。
   - manifest 要包含 `source=proto|extra`、API、exposure、label、effective policy。

4. **路由表的最终路径**
   - `Server.Routes()` 报告「最终部署路径」；`Surface` 保留 proto 原始路径。
   - 排查时同时给出 `full_method`、`proto_path`、`final_path`，避免前缀问题靠猜。

5. **testkit 网络认证**
   - `WithPrincipal` 只对进程内直调有效；网络测试需要
     `StaticAuthenticator` / `HeaderAuthenticator`。
   - 集成测试必须覆盖「HTTP 请求经过 gateway 后被 gRPC authz 拒绝」的路径。

6. **健康检查语义**
   - `/healthz` 只表示进程存活；`/readyz` 调 `Readiness`，失败返回 503。
   - gRPC health 状态要与 readiness 一致，不能一个说 SERVING、一个说 503。

7. **请求大小与超时**
   - HTTP `BodyLimit` 与 gRPC `MaxRecvMsgSize` 同步；默认 8MiB。
   - HTTP server 设置 ReadHeader/Read/Write/Idle timeout；gRPC 设置 keepalive。

8. **幂等与弃用**
   - `idempotent` 只是元数据，不自动实现幂等；需要时用可选 idempotency 模块。
   - `Deprecation{since,sunset,replacement}` 进文档与 manifest；HTTP 头可选。

9. **排障文档**
   - 至少覆盖：缺策略、重复路由、public 方法没 HTTP 注解、gateway 回环 IP 失真、
     HTTP 与 gRPC 双重 authz、OpenAPI 路径前缀不一致、CORS 预检 401。

10. **示例验收**
    - `example/simple`：Tier 0，proto 路由 + 一个 protected 方法 + 一个 public 方法。
    - `example/product`：多 service + 多 API 前缀 + OpenAPI 守卫 + 权限/角色/scope。
    - `example/platform`：legacy Provider + 自定义 Decider + extra route。

### 14.3 已拍板 / 仍待定

**已拍板（v3.0 按此实现）：**

| 决策 | 结论 |
|---|---|
| Gateway 连接 | 进程内 bufconn 默认；`Dial.InProcess=false` + `Target/TLS` 支持网络回环 |
| JSON 命名 | 默认 snake_case；`CamelCaseMarshaler()` 可选 |
| 注册方式 | 强制 `RegisterXxxHandlerClient` + 拦截器；禁用 `HandlerServer` |
| Codegen | v3.0 同步提供 `protoc-gen-grpcapi`，但手写 Registration 仍可跑 |
| 认证机制 | JWT/OIDC、Session/Cookie、API key+scope、Admin role/session |
| 认证模块 | v3.0 提供 JWT/Session/API key/Admin 参考实现，不只 SPI |
| CSRF | Double-submit cookie + SameSite，库提供中间件 |
| Streaming | server/client/bidi 全部支持；授权按方法配置，默认 open 时 |
| 多 API | v3.0 支持 public/internal/admin 多面，独立前缀/mux/docs |
| Admin 角色 | JWT/session claims 与独立 admin store **两者都有**，合并到 `admin_roles` |
| 迁移验收 | torchwood 优先，用 legacy Provider 零 proto 改动接入 |

**默认决策（已定，可覆盖）：**

1. **默认地址**：本地默认 `127.0.0.1:9060/8080` + `DisableGRPC/DisableHTTP`；
   生产必须显式覆盖。
2. **默认 access log**：关闭；启动路由表默认打印。dev 模式可显式开启。
3. **extra route 范围**：仅 health/webhook/static/OAuth callback。业务路由必须走
   proto；需要任意 handler 的项目用 Tier 1 的 `gateway.NewHandler` 自行承担
   guard/策略覆盖变弱的代价。
4. **OpenAPI 版本**：v3.0 只要求 OpenAPI v2（匹配 grpc-gateway openapiv2）；
   v3 loader 放 v3.1，`Document` 抽象不变。
5. **Connect/HTTP-only 适配器**：v3.0 不做，只保留 `policy/surface/guard` 边界。
6. **策略 manifest**：CI 默认生成并 diff；只做审计/文档，不作为运行时策略源。
7. **多 API**：v3.0 共享一个 gRPC server；独立端口/拦截器需要后续 `server.Group`。
8. **Streaming HTTP**：server-streaming 可走 HTTP；client-streaming/bidi 仅 gRPC，
   `EXPOSURE_PUBLIC` 启动失败。

这些是默认值，不是架构约束；项目可以通过配置覆盖。

### 14.4 建议的验证矩阵

| 维度 | 用例 |
|---|---|
| proto 路由 | public / authenticated / role / permission / scope / internal / deprecated |
| gateway | additional_bindings、custom verb、body/response_body、path params |
| 多 API | 独立前缀、同一 service 两个 API 面、独立 docs |
| 路由冲突 | 重复 verb+path、extra route 覆盖 proto、trailing slash |
| 认证 | JWT 过期/错 audience/JWKS 故障；session 固定/过期；API key 吊销/过期；admin store 故障 |
| CSRF | 缺 token、token 不匹配、Origin/Referer 非法、GET/OPTIONS 放行 |
| 授权 | 缺策略、缺 principal、权限不足、对象级、外部 Decider、admin 停用 |
| 流式授权 | open-time / per-message、client/bidi 非法 HTTP 暴露 |
| 错误体 | 非 proto body、Retry-After、脱敏、Status=0、Encoder 报错 |
| 流式 | unary、server-stream、client-stream、bidi（gRPC only） |
| 守卫 | OpenAPI v2、MapFS、前缀、缺 metadata、SDK 覆盖（v3 loader 在 v3.1） |
| 迁移 | legacy Provider、旧/新扩展共存、字段号冲突 |
| 性能 | Decider benchmark、路由查找、启动构建、内存分配 |

### 14.5 结论

当前设计的主路径已经对齐：**proto 定义路由 → `server.New` 自动装配 gRPC + gateway
→ gRPC 链统一 authn/authz/validate → extra route 只做逃生口 → guard 以 Surface 为准。**

第二轮复查的重点不是再加抽象，而是把「装配正确性」和「默认值边界」钉死：

- 不用 `RegisterXxxHandlerServer`。
- 同一 service 的 gRPC 注册只做一次。
- HTTP 与 gRPC 不重复授权。
- 网关回环 IP、CORS 预检、CSRF、请求大小、超时、readiness 都要有明确默认。
- 策略校验要拒绝「空组、空值、缺参数」这类静默放宽。

这些点修完，主路径才算真的「开箱即用且不会静默出错」。
