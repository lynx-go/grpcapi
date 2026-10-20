package main

import (
	"context"
	"testing"

	echov1 "github.com/lynx-go/grpcapi/example/echo/v1"
	"github.com/lynx-go/grpcapi/guard"
	"github.com/lynx-go/grpcapi/interceptor"
	"github.com/lynx-go/grpcapi/policy"
	"github.com/lynx-go/grpcapi/policy/protopolicy"
	"github.com/lynx-go/grpcapi/policy/scope"
	"google.golang.org/grpc"
)

func buildPolicies(t *testing.T) *policy.Set {
	t.Helper()
	set, err := policy.Build(context.Background(), policy.FromFiles(echov1.File_echo_proto), policy.Options{
		Provider: protopolicy.New(protopolicy.Options{}),
		Registry: policy.DefaultRegistry(),
	})
	if err != nil {
		t.Fatalf("policy.Build: %v", err)
	}
	return set
}

// 第 3 步的等价锁：注解收集结果与契约意图一致（方法级优先、服务级回落）。
func TestBuildMatchesContract(t *testing.T) {
	set := buildPolicies(t)

	shout, ok := set.Get("/example.echo.v1.EchoService/Shout")
	if !ok {
		t.Fatal("missing Shout policy")
	}
	if got := shout.EffectiveLabel(); got != "server" {
		t.Errorf("Shout label = %q, want server", got)
	}
	if len(shout.Policy.AnyOf) != 2 {
		t.Fatalf("Shout any_of = %+v, want role|scope", shout.Policy.AnyOf)
	}
	if shout.Policy.AnyOf[0][0].Kind != "role" || shout.Policy.AnyOf[1][0].Kind != "scope" {
		t.Fatalf("Shout any_of kinds = %+v", shout.Policy.AnyOf)
	}
	if got := shout.Policy.AnyOf[1][0].Values; len(got) != 1 || got[0] != "echoes:write" {
		t.Fatalf("Shout scope = %v", got)
	}

	hear, ok := set.Get("/example.echo.v1.EchoService/Hear")
	if !ok {
		t.Fatal("missing Hear policy")
	}
	if got := hear.EffectiveLabel(); got != "authenticated" {
		t.Errorf("Hear label = %q, want authenticated (service default)", got)
	}
	if len(hear.Policy.Require) != 1 || hear.Policy.Require[0].Kind != "authenticated" {
		t.Fatalf("Hear policy = %+v", hear.Policy)
	}

	ping, ok := set.Get("/example.echo.v1.EchoService/Ping")
	if !ok || !ping.Policy.Anonymous {
		t.Fatal("Ping should be anonymous")
	}
	if got := ping.EffectiveLabel(); got != "public" {
		t.Errorf("Ping label = %q, want public", got)
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

// scope 语言在 example 契约上的行为锁。
func TestScopeSatisfies(t *testing.T) {
	ss, err := scope.Parse([]string{"echoes:write"})
	if err != nil {
		t.Fatalf("scope.Parse: %v", err)
	}
	if !ss.Satisfies("echoes", "write") {
		t.Error("echoes:write 应满足 echoes/write")
	}
	if ss.Satisfies("echoes", "read") {
		t.Error("echoes:write 不应满足 echoes/read")
	}
	all, _ := scope.Parse([]string{"*"})
	if !all.Satisfies("echoes", "admin") {
		t.Error("* 应满足任意门")
	}
}

// 第 6 步：守卫 helper——registry 侧（swagger 侧需项目 openapiv2 生成物）。
func TestGuardRegistry(t *testing.T) {
	guard.AssertMethodCount(t, "example.echo.v1", 3)
}
