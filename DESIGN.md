# grpcapi 设计稿（v2.1 定稿）

> 把 torchwood 的「proto 声明 API + grpc-gateway 暴露」模式固化为 lynx 生态可复用库。
> 定稿日期：2026-09-23。经对抗审查 + 独立设计交叉验证 + 深度复查三轮评审。

## 1. 背景与目标

torchwood 以如下方式开发 API：proto 注解声明路由（`google.api.http`）、authz 策略
（自定义 `method_auth`/`service_auth` 扩展，策略唯一声明源）、请求形状校验
（`buf.validate`）与 OpenAPI 扩展；buf 四插件生成到独立 genproto module；运行时基于
lynx 装配 gRPC server（六层拦截器链）+ grpc-gateway（同地址拨号、统一错误处理器）；
守卫测试族（swagger↔policy 一致性、authz 矩阵、SDK 覆盖）锁定全链一致。

本库把其中**与 torchwood 标识符零耦合的机制**固化下来，使新项目按同样约定写 proto
即可获得：authz 收集 + 启动 fail-closed 断言、标准拦截器链、gateway 装配件、守卫
测试 helper。

**第一受益人必须是 torchwood 自己**：阶段 1 即删除其 183 行 enum 映射层
（`runtime/authz_policy.go`）、断言钩子化、行为零变更。即使库终身只有 torchwood 一个
用户，迁移也不亏。

## 2. 切分原则

**主判据**：一段代码若不引用任何 torchwood 标识符（服务名前缀、资源/角色词表、
Principal 结构、产品路径）就能写出完备单元测试，则它是机制，进库；否则留项目。

派生规则：

1. **词表主权归项目**：值域因项目而异的维度（admin 角色、scope 资源）一律 string，
   库只提供「注册词表 + fail-closed 校验」框架；值域稳定的语义维度（AccessLevel
   五档、ScopeOp 三档）保持枚举，由库持有。
2. **对外契约不上移**：错误体 JSON、`x-<project>-access` 扩展名、路由路径、
   ErrorResponse proto 是各项目对客户端的产品承诺，库只提供构造器/参数位。
3. **机制包零框架依赖**：`authz` 包只依赖 protobuf（不 import grpc/lynx），domain
   纯净分层的项目可直接引用；`guard` 为 test-only 包。

### 进库 / 留项目清单

| 进库（机制） | 留项目（策略/契约） |
|---|---|
| authz 扩展 proto 及 genproto | 业务 proto 与 `authzFileDescriptors` 清单 |
| 收集器（descriptor 遍历 + 扩展解析） | AdminRole/ScopeResource 词表值域断言 |
| PolicySet/MethodPolicy 纯类型 | PUBLIC 白名单、面前缀断言、project_id 不变量 |
| 可注入断言框架（内置通用断言 + 项目钩子） | scope 目标提取、console 会话规则 |
| 核心 scope 语言（`*`/`all`/`resource`/`resource.op`） | 实例限定 scope（`databases:blog`）与自定义 scope |
| validate / clientInfo 拦截器 + trusted proxies | auth 拦截器（阶段 2 才骨架化）、rateLimit/audit/usage 实现 |
| 框架服务豁免（grpc.health.v1./grpc.reflection.） | ErrorResponse proto 与 code→error_code 映射 |
| gateway 装配件（mux/marshaler/matcher/错误处理/拨号） | 顶层单端口路由（landing/realtime/console SPA） |
| 守卫测试 helper（swagger 族/矩阵/registry 遍历） | 具体快照常量与项目文案 |

## 3. 库形态

- **Go module** `github.com/lynx-go/grpcapi`，依赖单向：`lynx ← grpcapi ← 项目`。
- **proto 模块** `proto/grpcapi/v1/authz.proto`（package `grpcapi.v1`），发布 BSR
  （`buf.build/<org>/grpcapi`），项目 `buf.yaml` deps 引用——与 torchwood 现有三个
  BSR dep 同模式。
- **扩展生成代码单点生成**：只生成一次，放库的 `genproto/` 子 module
  （`go_package` 指向 `github.com/lynx-go/grpcapi/genproto/grpcapi/v1;grpcapiv1`）。
  项目 `buf generate` 不重生成依赖模块文件，Go 类型从库 module import——仿
  googleapis `annotations.proto` 模式，杜绝多副本漂移。库 CI 断言 proto 源与
  genproto 同 PR。
- **example 目录**：可编译最小项目 = 最小接入面活文档。README 接入清单 ≤ 6 步
  （buf dep → go.mod → 词表 → 装配 → 一条守卫 → 启动断言），example 不得超出该清单
  引入额外必需步骤。不做脚手架命令。

### 包结构

```
grpcapi/
  authz/        # 零 grpc/lynx 依赖
    policy.go       # AccessLevel/ScopeOp/ScopeRule/MethodPolicy/PolicySet
    build.go        # Build(files, Options) 收集器
    vocabulary.go   # Vocabulary 必填词表 + 内置词表断言
    assert.go       # Assertion 接口 + 内置通用断言
    scope.go        # ScopeSet 四形态解析与匹配
  interceptor/
    framework.go    # FrameworkExempt + AssertAllRegisteredHavePolicy
    chain.go        # Assemble（Slot 标记 + 构造期顺序断言，~50 行，非框架）
    clientinfo.go   # Client-IP/UA + trusted proxies
    validate.go     # protovalidate 链尾
  gateway/
    errors.go       # ErrorBodyBuilder + NewErrorHandler（Retry-After/脱敏/499 内置）
    marshaler.go    # protojson snake_case
    headers.go      # matcher 构造器（内置踩坑结论）
    mux.go / dial.go
  guard/            # test-only
    swagger.go / matrix.go / registry.go
  contextx/         # ClientInfo / audit holder 可变槽（原 contexts 通用子集）
  proto/grpcapi/v1/authz.proto
  genproto/         # 子 module
  example/
```

## 4. proto 扩展定义

```protobuf
syntax = "proto3";
package grpcapi.v1;
import "google/protobuf/descriptor.proto";

enum AccessLevel {
  ACCESS_LEVEL_UNSPECIFIED = 0;
  ACCESS_LEVEL_PUBLIC = 1;
  ACCESS_LEVEL_END_USER = 2;
  ACCESS_LEVEL_SERVER = 3;
  ACCESS_LEVEL_PERMISSION = 4;
  ACCESS_LEVEL_SYSTEM = 5;
}

enum ScopeOp {
  SCOPE_OP_UNSPECIFIED = 0;
  SCOPE_OP_READ = 1;
  SCOPE_OP_WRITE = 2;
  SCOPE_OP_ADMIN = 3;
}

message APIKeyScope {
  string resource = 1;   // 词表主权在项目，收集期经 Vocabulary fail-closed 校验
  ScopeOp op = 2;
}

message MethodAuth {
  AccessLevel access = 1;
  repeated string permissions = 2;
  repeated string admin_roles = 3;
  APIKeyScope api_key_scope = 4;
}

message ServiceAuth { AccessLevel default_access = 1; }

extend google.protobuf.MethodOptions  { MethodAuth method_auth = 52301; }
extend google.protobuf.ServiceOptions { ServiceAuth service_auth = 52302; }
```

## 5. 关键接口

### authz 包

```go
type AccessLevel int32   // Unspecified/Public/EndUser/Server/Permission/System
type ScopeOp string      // "read"/"write"/"admin"

type ScopeRule struct{ Resource string; Op ScopeOp }

type MethodPolicy struct {
    Method, Service string       // "/pkg.Svc/Method" 形态
    Access          AccessLevel
    Permissions     []string     // 原样透传，词表主权在项目
    AdminRoles      []string
    Scope           *ScopeRule   // nil = 不对 key 开放
    RequestFields   []string     // 请求消息全部字段名（排序投影）
    IsStreaming     bool
}

type PolicySet struct{ /* ... */ }
func (s *PolicySet) Get(method string) (MethodPolicy, bool)
func (s *PolicySet) Methods() []MethodPolicy
func (s *PolicySet) ScopeRule(method string) *ScopeRule
func (s *PolicySet) AllowedAdminRoles(method string) []string

type Vocabulary struct{ ScopeResources []string }  // 必填：有 Scope 声明而词表为空 → 构造失败

type Assertion interface {
    AssertPolicy(p MethodPolicy) error   // 逐方法（值域、白名单、不变量）
    AssertSet(s *PolicySet) error        // 全局（可选实现，返回 nil 即跳过）
}

type Options struct {
    Vocabulary     Vocabulary
    AllowStreaming bool                 // 默认 false：流式方法 fail-closed
    Assertions     []Assertion          // 项目断言钩子
}

func Build(files []protoreflect.FileDescriptor, opts Options) (*PolicySet, error)
// method_auth 优先，缺省回落 service_auth.default_access；内置断言：
// access 非 UNSPECIFIED；Server 面必带 scope；Permission 面必带 permissions；
// scope.resource 在词表（不可关闭）；死 scope 检测；streaming 门；违例聚合单一 error。

type ScopeSet []string
func (ss ScopeSet) Satisfies(rule ScopeRule) bool   // */all、resource、resource.op 四形态
```

### interceptor / gateway 包

```go
// interceptor
func FrameworkExempt(fullMethod string) bool
func AssertAllRegisteredHavePolicy(srv *grpc.Server, set *authz.PolicySet) error
type Slot int  // SlotClientInfo, SlotAuth, SlotRateLimit, SlotAudit, SlotUsage, SlotValidate
func Assemble(items ...struct{ Slot; grpc.UnaryServerInterceptor }) ([]grpc.UnaryServerInterceptor, error)
// 构造期断言：Slot 不得乱序、缺 SlotClientInfo 头、SlotValidate 收尾 → 启动即红

// gateway
type ErrorBodyBuilder interface {
    Build(code codes.Code, message, errorID string) proto.Message
    MapErrorCode(code codes.Code) any
}
type HTTPOptions struct {
    CodeToHTTP       map[codes.Code]int  // 缺省内置表（含 Canceled→499）
    SanitizeInternal bool                // 默认 true：Internal/Unknown 脱敏 + error_id
}
func NewErrorHandler(b ErrorBodyBuilder, o HTTPOptions) runtime.ErrorHandlerFunc
// Retry-After（erdetails.RetryInfo）提取、脱敏、499 映射全部内置。

func IncomingMatcher(extraAllow ...string) func(string) (string, bool)
// 内置：authorization 恒拒绝（双写 401 坑）；cookie/x-api-key/x-request-id/
// idempotency-key 放行；项目追加 x-<project>-project 等。
func OutgoingMatcher(direct ...string) func(string) (string, bool)
// 内置：set-cookie 直透；项目追加专属头。
type MuxOptions struct { ErrorHandler runtime.ErrorHandlerFunc; IncomingExtra, OutgoingDirect []string }
func NewMux(o MuxOptions) *runtime.ServeMux
func LocalEndpoint(grpcAddr string) string
func Dial(ctx context.Context, addr string, cfg DialConfig) (*grpc.ClientConn, error)
// 同地址拨号（LocalEndpoint 归一），留 TLS 注入口（默认 insecure）。
type RegisterFunc func(ctx context.Context, mux *runtime.ServeMux, conn grpc.ClientConnInterface) error
func Register(ctx context.Context, mux *runtime.ServeMux, conn grpc.ClientConnInterface, fns ...RegisterFunc) error
```

### guard 包（test-only）

```go
type SwaggerOptions struct {
    GenprotoSubdirs  []string
    Files            []protoreflect.FileDescriptor
    Policies         *authz.PolicySet
    AccessExtension  string   // 常量由库提供，消除手写拼错
    ErrorResponseRef string   // 动态查找生成物 ref，不硬编码
    MinFiles, MinOps int      // 空参/零下限直接 t.Fatal 拒绝空转
}
func SwaggerAccessMatches(t *testing.T, o SwaggerOptions)
func SwaggerSnakeCaseProperties(t *testing.T, dirs ...string)
func SwaggerNoDefinition(t *testing.T, dirs []string, banned string)
func RenderMatrix(set *authz.PolicySet, o MatrixOptions) ([]byte, error)
func AssertDocUnchanged(t *testing.T, rendered []byte, path string)
```

## 6. 关键裁决（六条，含修订后理由）

1. **新字段号 52301/52302 + 单 PR 一次性切换，无双读。** 扩展字段号在 wire 层没有
   package 命名空间：同号不同型（enum varint vs string LEN）的两套扩展并存于一个
   二进制时 `GetExtension` 静默跳过返回零值，注解丢失后方法回落 service 默认档
   （PERMISSION 静默降级为 SERVER），无任何报错。torchwood 是单仓库，约 34 个 proto
   文件纯机械替换，单 PR 原子完成即可；双读是为不存在的灰度需求付出的永久复杂度。
   新号避开 torchwood 历史号段（52001/52002），防御迁移窗口与第三方引用旧模块的
   混用态。
2. **词表 string 化，基准 = 项目 domain 现网持久化形态。** torchwood 已核实：proto
   enum（`SCOPE_RESOURCE_OAUTH_PROVIDERS`）从未对外——well-known 下发是手写 JSON
   domain string、SDK 契约锚 `domainauth.AllScopeResources` Go 常量、API key 存量
   scope 数据是 domain 形态（`oauthproviders`，无下划线）。string 化不构成对外契约
   变更；`Vocabulary` 必填 + 「resource/op 在词表内」为不可关闭的内置断言（词表缺失
   即构造失败，杜绝 fail-open 窗口）。迁移替换表从即将删除的 enum 映射层机械生成，
   不手写。
3. **错误体构造器注入，机制内置。** `ErrorBodyBuilder` 收 `(code, message, errorID)`；
   Retry-After 提取、Internal 脱敏 + error_id、Canceled→499 映射全部内置进库
   （torchwood 有 `errors_retry_after_test.go` 锁定，等价性由阶段 0 golden + 该测试
   双重保证）；code→项目 error_code 映射经 `MapErrorCode` 注入。库可选提供
   `grpcapi.v1.ErrorResponse` 标准错误体（新项目白拿，torchwood 不用）。
4. **断言框架可注入规则集。** torchwood `AssertSemantic` 主体（五个白名单、`torchwood.`
   面前缀、ClassifyTier 档位模型、END_USER 归一）全部是项目策略，改造为
   `Assertion` 钩子注册进 `Build`；END_USER 归一从收集器拆出。库保留的内置断言仅
   通用语义（见 §5 authz.Build 注释）。
5. **auth 拦截器阶段 2 骨架化。** 阶段 1 留项目原样跑通。骨架化判据：torchwood 全部
   auth 行为测试不改断言、只改装配地通过。六条安全微语义（PUBLIC 面无效 key 一律
   401 不降级、多凭证拒绝、authorization matcher 双写坑、deny audit WithoutCancel+3s、
   失败限流只计失败、admin 会话多值 project 头拒绝）逐条对位钩子，无对照表不开工。
6. **contexts 门面保留。** 151 个文件引用 `internal/pkg/contexts`；门面化（公开 API
   不变、内部委托库 `contextx`）使迁移 PR 波及面收缩约 150 个文件。直连清理放
   阶段 3 甚至不做。

## 7. 迁移计划（torchwood）

**阶段 0 —— golden 基线（不动依赖）**
现 `BuildMethodPolicies + AssertSemantic` 全量输出序列化落
`cmd/server/internal/runtime/testdata/policies.golden.json`，新增等价测试逐条比对。
admin_roles enum→string、RequestHasProjectID→RequestFields 的形态差以归一化形态比对。
这是后续一切切换的等价性证明基准与回滚判据。

**阶段 1 —— 库首版 + 原子切换（单 PR 或紧邻双 PR）**
建 grpcapi repo 全量落地（auth 拦截器除外）；torchwood：脚本替换全部业务 proto 的
import 与注解前缀（值名映射 ACCESS_SERVER→ACCESS_LEVEL_SERVER 等从映射层生成）；
删 `proto/shared/v1/authz.proto` 与 `runtime/authz_policy.go`；`policy.go` 类型删除、
断言钩子化；validate/clientInfo 换库；`assertRegisteredMethodsHaveAuthz` 换库；
gateway 装配件换库（ErrorResponse 经 ErrorBodyBuilder 注入）；守卫换 guard helper；
contexts 门面化。验收：golden 等价 + 全守卫绿 + `mise run test` 全量绿。

**阶段 2 —— auth 骨架 + 端点型拦截器**
见裁决 5。

**阶段 3 —— 新项目接入面**
example + 文档；torchwood 文档策略源描述改指 grpcapi。

**回滚**：阶段 1 revert 单 PR（proto/genproto/代码同 PR）；golden 保留至阶段 2 结束。

## 8. 发布工程

- **版本策略**：0.x（minor 可破坏，migration note 义务），对齐 torchwood SDK 惯例。
- **本地开发**：go.work 编排 grpcapi + torchwood 双仓（torchwood 主 go.mod 以
  `replace github.com/lynx-go/grpcapi => ../grpcapi` 参与工作区）；**发布时序**：
  grpcapi 先发版（BSR push + Go tag 同 PR），torchwood 升 go.mod 引用后才能进
  Dokploy git 构建（本地 replace 在 git 构建环境不存在）。
- **版本协调**：四 module（torchwood、torchwood/genproto、grpcapi、grpcapi/genproto）
  对 grpc/protobuf/grpc-gateway 版本求交集；库 CI 锁 proto↔genproto 同 PR；README
  维护「grpcapi 版本 ↔ BSR revision」对应表，项目 go.mod 与 buf.lock 同 PR 升级。
- **buf breaking**：torchwood 迁移 PR 中 MethodOptions 扩展变更会标红，走显式豁免
  窗口（一次性）。

## 9. v1 非目标（显式）

- **streaming**：全链拦截器仅 Unary，流式方法启动断言失败。v1 文档与断言报错明示。
  支持需另立设计（审计/认证的 per-message 语义）。
- **顶层单端口路由组合**：landing/WS/console SPA 是产品路径，留项目。
- **脚手架命令**：example 目录即文档。
- **authz-matrix 渲染器进库**：torchwood 文案专属，等第二个真实消费者再议。

## 10. Rejected Alternatives

- **ConnectRPC（bufbuild/connect-go）**：「单 handler 同服 gRPC + HTTP JSON、无回环
  拨号」的现代解法。否决理由：torchwood 188 RPC 的 REST 契约（custom verb 路由
  `:replay`、cookie 认证流、multipart 混挂、Agent 消费的 OpenAPI）建立在
  grpc-gateway 语义上，换 Connect 是产品级变更，超出「固化已验证模式」的范畴。若
  从零开始会重新评估；记录在此供未来读者。
- **本仓库 pkg/ 内沉淀**：只服务单仓库，模式的复用价值无法体现。
- **贡献回 lynx 本体**：lynx 是通用运行时，authz 语义会让它变重；独立库依赖方向
  单向（lynx ← grpcapi ← 项目）。

## 11. 已知限制

- **扩展演进**：`MethodAuth` 未来加新门字段时，旧版本收集器静默忽略未知字段——
  新项目用新门 + 旧库 = 权限静默变宽。协议层无法防御，唯一防线是 BSR buf.lock 与
  go.mod 同 PR 升级 + 本节声明。升级库前读 migration note。
- **openapiv2 生成器内部行为**：guard 的 ErrorResponseRef 动态查找仍依赖生成器命名
  规则的稳定性；插件大版本升级需重验。
- **grpc-go 拨号 API**：`grpc.Dial` 走向弃用（`grpc.NewClient`），拨号工厂预留跟随
  升级面。
