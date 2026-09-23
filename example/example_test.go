package main

import (
	"testing"

	"github.com/lynx-go/grpcapi/authz"
	echov1 "github.com/lynx-go/grpcapi/example/echo/v1"
	"github.com/lynx-go/grpcapi/guard"
	"github.com/lynx-go/grpcapi/interceptor"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func buildPolicies(t *testing.T) *authz.PolicySet {
	t.Helper()
	set, err := authz.Build(
		[]protoreflect.FileDescriptor{echov1.File_echo_proto},
		authz.Options{Vocabulary: authz.Vocabulary{ScopeResources: []string{"echoes"}}},
	)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return set
}

// 第 3 步的等价锁：注解收集结果与契约意图一致（方法级优先、服务级回落）。
func TestBuildMatchesContract(t *testing.T) {
	set := buildPolicies(t)

	want := map[string]authz.AccessLevel{
		"/example.echo.v1.EchoService/Shout": authz.AccessServer,  // method_auth 显式
		"/example.echo.v1.EchoService/Hear":  authz.AccessEndUser, // 回落 service_auth
		"/example.echo.v1.EchoService/Ping":  authz.AccessPublic,  // method_auth 显式
	}
	for method, access := range want {
		got, ok := set.Get(method)
		if !ok {
			t.Fatalf("missing policy for %s", method)
		}
		if got.Access != access {
			t.Errorf("%s: access = %v, want %v", method, got.Access, access)
		}
	}

	if rule := set.ScopeRule("/example.echo.v1.EchoService/Shout"); rule == nil ||
		rule.Resource != "echoes" || rule.Op != authz.ScopeWrite {
		t.Errorf("Shout scope = %+v, want echoes/write", set.ScopeRule("/example.echo.v1.EchoService/Shout"))
	}
	if rule := set.ScopeRule("/example.echo.v1.EchoService/Hear"); rule != nil {
		t.Errorf("Hear scope = %+v, want nil（END_USER 不对 key 开放）", rule)
	}
}

// 第 5 步的等价锁：启动断言对齐齐全的策略面放行。
func TestAssertAllRegisteredHavePolicy(t *testing.T) {
	set := buildPolicies(t)
	srv := grpc.NewServer()
	echov1.RegisterEchoServiceServer(srv, &echoServer{})
	if err := interceptor.AssertAllRegisteredHavePolicy(srv, set); err != nil {
		t.Fatalf("AssertAllRegisteredHavePolicy: %v", err)
	}
}

// scope 语言（四形态）在 example 契约上的行为锁。
func TestScopeSatisfies(t *testing.T) {
	ss, err := authz.ParseScopeSet([]string{"echoes.write"})
	if err != nil {
		t.Fatalf("ParseScopeSet: %v", err)
	}
	if !ss.Satisfies(authz.ScopeRule{Resource: "echoes", Op: authz.ScopeWrite}) {
		t.Error("echoes.write 应满足 echoes.write")
	}
	if ss.Satisfies(authz.ScopeRule{Resource: "echoes", Op: authz.ScopeRead}) {
		t.Error("echoes.write 不应满足 echoes.read")
	}
	all, _ := authz.ParseScopeSet([]string{"*"})
	if !all.Satisfies(authz.ScopeRule{Resource: "echoes", Op: authz.ScopeAdmin}) {
		t.Error("* 应满足任意门")
	}
}

// 第 6 步：守卫 helper——registry 侧（swagger 侧需项目 openapiv2 生成物，
// 用法见 guard.SwaggerAccessMatches 文档与 torchwood 的 grpc_swagger_test.go）。
func TestGuardRegistry(t *testing.T) {
	guard.AssertMethodCount(t, "example.echo.v1", 3)
}
