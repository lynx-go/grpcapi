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
4. 装配：`interceptor.Assemble` 组拦截器链，`gateway.NewMux` + `gateway.DialLocal` +
   `gateway.Register` 组 HTTP 面。
5. 启动断言：`interceptor.AssertAllRegisteredHavePolicy(srv, set)`。
6. 挂一条守卫：`guard.SwaggerAccessMatches(t, ...)`。

可运行参考：[example/](./example/)。

## 版本

0.x：minor 可携带破坏性变更，见各 tag 的 migration note。升级前请同步项目
`buf.lock` 与 `go.mod`（同 PR）。
