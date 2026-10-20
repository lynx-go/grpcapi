# v2 → v3 迁移手册（torchwood 优先）

> v3 不保留旧 `authz` 包与 `grpcapi/v1/authz.proto`。本手册给出 torchwood 的
> 两种切换路径；推荐 **A. vendored legacy proto + legacyProvider**，业务 proto
> 零改动，先完成运行时/守卫等价性，再逐步迁到 `policy.proto`。

## 1. 迁移映射

| v2 | v3 |
|---|---|
| `authz.Build(files, Options{...})` | `policy.Build(ctx, source, Options{Provider: ...})` |
| `authz.PolicySet` | `policy.Set` |
| `authz.MethodPolicy` | `policy.Operation` |
| `authz.AccessLevel_*` | 项目 `legacyProvider` 展开成 `policy.Policy` |
| `authz.ScopeSet` / `ScopeRule` | `policy/scope` 的 `Set.Satisfies(resource, op)` |
| `authz.Vocabulary{ScopeResources}` | `policy.Vocabulary{"scope": ...}` |
| `interceptor.ChainItem{Slot,...}` | `interceptor.Stage{Name,Order,...}` |
| `gateway.ErrorBodyBuilder` | `gateway.ErrorEncoder` / `DefaultErrorEncoder` |
| `guard.SwaggerAccessMatches` | `guard.OpenAPIv2` + `guard.AssertDocuments` / `guard.Run` |
| `guard.AssertMethodCount`（global registry） | `guard.AssertSurfaceMethodCount` |
| `guard.AssertServiceCoverage`（global registry） | `guard.AssertSurfaceCoverage` |

## 2. 路径 A：vendored legacy proto + legacyProvider（推荐）

### 2.1 保留旧注解，换 Go 包路径

业务 proto 继续 `import "grpcapi/v1/authz.proto"`，但把旧 proto 文件 vendored 到
torchwood：

```text
torchwood/proto/third_party/grpcapi/v1/authz.proto
```

- 内容从 grpcapi v0.1.0 复制。
- 把 `go_package` 改为：
  ```protobuf
  option go_package = "github.com/<org>/torchwood/genproto/legacy/grpcapi/v1;legacypb";
  ```
- 项目 `buf.yaml` 把 `proto/third_party` 作为独立模块 / 或用 `excludes` 处理；
  `buf.gen.yaml` 正常生成 legacy Go 包。
- 这样 v3 主库不再携带旧 proto；torchwood 的旧注解仍能编译。

### 2.2 实现 legacyProvider

```go
package runtime

import (
    "context"

    legacypb "github.com/<org>/torchwood/genproto/legacy/grpcapi/v1"
    "github.com/lynx-go/grpcapi/policy"
    "google.golang.org/genproto/googleapis/api/annotations"
    "google.golang.org/protobuf/proto"
    "google.golang.org/protobuf/reflect/protoreflect"
)

type legacyProvider struct{}

func (legacyProvider) File(fd protoreflect.FileDescriptor) (policy.FileSpec, bool, error) {
    // 可返回 API 面/schema 版本；torchwood 可按包前缀分 public/server/console。
    return policy.FileSpec{API: apiOfPackage(string(fd.Package())), SchemaVersion: 1}, true, nil
}

func (legacyProvider) Service(sd protoreflect.ServiceDescriptor) (policy.ServiceSpec, bool, error) {
    opts := sd.Options()
    if opts == nil {
        return policy.ServiceSpec{}, false, nil
    }
    ext := proto.GetExtension(opts, legacypb.E_ServiceAuth)
    sa, _ := ext.(*legacypb.ServiceAuth)
    if sa == nil {
        return policy.ServiceSpec{}, false, nil
    }
    p, err := expandAccess(sa.GetDefaultAccess(), nil, nil)
    if err != nil {
        return policy.ServiceSpec{}, false, err
    }
    return policy.ServiceSpec{DefaultPolicy: &p}, true, nil
}

func (legacyProvider) Method(md protoreflect.MethodDescriptor) (policy.MethodSpec, bool, error) {
    opts := md.Options()
    if opts == nil {
        return policy.MethodSpec{}, false, nil
    }
    ext := proto.GetExtension(opts, legacypb.E_MethodAuth)
    ma, _ := ext.(*legacypb.MethodAuth)
    if ma == nil {
        return policy.MethodSpec{}, false, nil
    }
    p, err := expandAccess(ma.GetAccess(), ma.GetAdminRoles(), ma.GetApiKeyScope())
    if err != nil {
        return policy.MethodSpec{}, false, err
    }
    exposure := policy.ExposureInternal
    if hasHTTP(opts) {
        exposure = policy.ExposurePublic
    }
    return policy.MethodSpec{Policy: &p, Exposure: exposure}, true, nil
}
```

`expandAccess` 的语义：

```text
PUBLIC       -> { anonymous: true }
END_USER     -> { require: [ principal_kind(user) ] }
SERVER       -> { any_of: [
                    { require: [ admin_role(admin_roles...) ] },
                    { require: [ scope(resource) ] },
                  ] }
PERMISSION   -> { require: [ permission(match=ALL, permissions...) ] }
SYSTEM       -> 项目自定义 kind 或 error（v3 默认禁用）
```

- `api_key_scope { resource, op }` → `scope` requirement value `resource` 或
  `resource:op`（v3 scope 语言；旧 `resource.op` 也兼容）。
- `admin_roles` 读 `admin_roles` claim（不是普通 `roles`）。
- `hasHTTP` 检查 `annotations.E_Http`；有注解 → PUBLIC/文档面，无注解 → INTERNAL。
  有 `EXPOSURE_HIDDEN` 需求的项目可以在 legacyProvider 里用自己规则覆盖。

### 2.3 Registry 与词表

```go
reg, err := policy.NewRegistry(
    policy.KindAuthenticated(),
    policy.KindClaim(),
    policy.KindPrincipal(),
    policy.ClaimKind("role", "roles", policy.MatchAny),
    policy.ClaimKind("admin_role", "admin_roles", policy.MatchAny),
    policy.ClaimKind("permission", "permissions", policy.MatchAll),
    scope.Kind(scope.Options{
        Claim:              "scopes",
        VocabularyDomain:   "scope",
        RequireVocabulary:  true,
        DisallowWildcard:   false,
    }),
)
```

```go
set, err := policy.Build(ctx,
    policy.FromFiles(authzFileDescriptors()...),
    policy.Options{
        Provider:   legacyProvider{},
        Registry:   reg,
        Vocabulary: policy.NewVocabulary(map[string][]string{
            "scope": domainauth.AllScopeResources,
        }),
    })
```

- `scope.Kind` 替换默认精确匹配 scope，保留 torchwood 的 `resource[.op]` 语义。
- 旧 `authorization` 头/API key/session 认证器继续由 torchwood 的 auth 拦截器提供；
  v3 只消费 `Principal`。

### 2.4 运行时切换

- `domainauth.PolicySet` 改为 `*policy.Set`，或保留 `domainauth` 门面内部委托。
- `authz.Build` 替换为 `policy.Build` + `legacyProvider`。
- `authz.NewPolicySet`（测试）替换为 `policy.NewSet`。
- `authz.ScopeSet` 替换为 `policy/scope.Set`；匹配调用 `Satisfies(resource, op)`。
- `interceptor.AssertAllRegisteredHavePolicy` 改收 `*policy.Set`，签名已对齐。
- `interceptor.ChainItem` → `interceptor.Stage`；`SlotAuth` → `StageAuthz`。
- `gateway.ErrorBodyBuilder` → `gateway.ErrorEncoder`；旧错误体可包一层适配器。

### 2.5 Golden manifest 等价性

1. 用 v2 的 `buildMethodPolicies` 输出（access/scope/roles/permissions）生成
   `testdata/policies.golden.json`。
2. 用 v3 `policy.Build` + `legacyProvider` 构建 `policy.Set`，输出
   `set.Manifest().JSON()`。
3. 归一化差异（enum→string、`resource.op`→`resource:op`、admin_roles 独立 claim），
   逐方法比对：
   - access 档位 → 展开后的 requirement 树
   - scope resource/op
   - permissions 集合
   - admin_roles 集合
   - streaming 方法与 StreamAuth
   - exposure/label
4. 任何差异必须显式 review；测试全绿不能替代 golden 比对。

### 2.6 守卫迁移

```go
docs, _ := guard.OpenAPIv2(os.DirFS("genproto"), guard.OpenAPIv2Options{
    Pattern: "*.swagger.json",
})
guard.Run(t, guard.SuiteConfig{
    Surface: surf,
    Docs:    docs,
    Policy: guard.MatchOptions{
        MetadataKey:   "x-torchwood-access",
        ServiceLabel:  legacyServiceLabel,
        ErrorRef:      func(guard.Document, guard.DocumentOperation) (string, bool) {
            return "#/definitions/v1ErrorResponse", true
        },
        MinOperations: 188,
    },
    Naming: guard.SnakeCase,
    SDK: &guard.SDKConfig{API: "server", Prefix: "torchwood.server.v1", Client: sdkClient},
    Matrix: &guard.MatrixConfig{Path: "docs/authz-matrix.md", Options: ...},
})
```

- `x-torchwood-access` 继续由现有生成管线注入；v3 只消费。
- `ServiceLabel` 从 legacy `service_auth.default_access` 映射到 label
  (`public/end_user/server/permission/system`)。
- 旧 `guard.SwaggerAccessMatches` 可以逐条替换为 `AssertDocuments`/`Suite`。

## 3. 路径 B：一次性 codemod 到 `policy.proto`

适合 proto 文件较少的项目：

1. `import "grpcapi/v1/authz.proto"` → `import "grpcapi/v1/policy.proto"`。
2. `service_auth.default_access` → `service.default_policy`。
3. `method_auth` 字段 → `policy`：
   - PUBLIC → `{ anonymous: true }`
   - END_USER → `{ authenticated: true }` 或 `principal_kind(user)`
   - SERVER + admin_roles + api_key_scope → `{ any_of: [...] }`
   - PERMISSION + permissions → `{ permissions: [...] }`
   - SYSTEM → 删除/项目自定义
4. 重新 `buf generate`，删除 legacy proto/生成物。
5. 跑路径 A 的 golden manifest 对比，确认等价后再删除 legacyProvider。

## 4. 回滚

- v2.1 保留 tag；阶段 1 的 proto/代码/golden 同 PR，可单 PR revert。
- 不做双读：v2 与 v3 扩展字段号不同，但同一二进制同时加载会依赖 `GetExtension`
  的静默行为；迁移期只允许一个 Provider 生效。
- golden manifest 保留到 torchwood 全量切换完成后再删除。

## 5. 验收清单

- [ ] `policy.Build` + `legacyProvider` 产出与 v2 golden 逐方法等价
- [ ] API key scope 四形态（`*`/`all`/resource/resource.op）行为不变
- [ ] PERMISSION/permissions、SERVER/admin_roles 行为不变
- [ ] streaming 方法 open-time 授权通过；per-message 需求单独验证
- [ ] public 面无效凭证仍 401，不降级
- [ ] gateway 错误体/header 行为不变
- [ ] `guard.Run` 的 OpenAPI policy/naming/banned/SDK/matrix 全绿
- [ ] `server.New` 装配路由表与旧启动注册面一致
- [ ] 全量 `go test -race ./...` 与 CI 通过
