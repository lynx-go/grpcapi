package interceptor_test

import (
	"context"
	"strings"
	"testing"

	"github.com/lynx-go/grpcapi/interceptor"
	"github.com/lynx-go/grpcapi/policy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"google.golang.org/protobuf/types/known/emptypb"
)

// TestFrameworkExempt 校验框架服务前缀白名单。
func TestFrameworkExempt(t *testing.T) {
	cases := []struct {
		fullMethod string
		want       bool
	}{
		{"/grpc.health.v1.Health/Check", true},
		{"/grpc.health.v1.Health/Watch", true},
		{"/grpc.reflection.v1.ServerReflection/ServerReflectionInfo", true},
		{"/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo", true},
		{"/testshop.v1.Shop/Get", false},
		{"/testgrpc.health.v1.Health/Check", false}, // 前缀必须从服务名首段起
		{"grpc.health.v1.Health/Check", false},      // fullMethod 必带前导斜杠
		{"", false},
	}
	for _, tc := range cases {
		if got := interceptor.FrameworkExempt(tc.fullMethod); got != tc.want {
			t.Fatalf("FrameworkExempt(%q) = %v, want %v", tc.fullMethod, got, tc.want)
		}
	}
}

// buildTestPolicySet 直接构造策略集：声明 services 中的每个方法都有策略。
// 用于模拟「proto 已注解」的侧，grpc server 侧可注册超集方法以制造漂移。
func buildTestPolicySet(t *testing.T, services map[string][]string) *policy.Set {
	t.Helper()
	var ops []policy.Operation
	for svcName, methods := range services {
		for _, m := range methods {
			ops = append(ops, policy.Operation{
				ID:       "/" + svcName + "/" + m,
				Kind:     policy.KindGRPC,
				Service:  svcName,
				Exposure: policy.ExposureInternal,
				Policy:   policy.Policy{Anonymous: true},
			})
		}
	}
	set, err := policy.NewSet(ops...)
	if err != nil {
		t.Fatalf("policy.NewSet: %v", err)
	}
	return set
}

// registerTestService 手工注册一个由桩 handler 组成的服务（等价于
// 生成代码 RegisterXServer 对 GetServiceInfo 的贡献，无需生成码）。
func registerTestService(srv *grpc.Server, serviceName string, methods ...string) {
	desc := &grpc.ServiceDesc{
		ServiceName: serviceName,
		// 空接口：RegisterService 的反射检查要求 HandlerType 非空且
		// 实现（struct{}）满足之，桩服务无业务接口可用。
		HandlerType: (*any)(nil),
	}
	for _, m := range methods {
		desc.Methods = append(desc.Methods, grpc.MethodDesc{
			MethodName: m,
			Handler: func(_ any, _ context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
				req := &emptypb.Empty{}
				if err := dec(req); err != nil {
					return nil, err
				}
				return req, nil
			},
		})
	}
	srv.RegisterService(desc, struct{}{})
}

func TestAssertAllRegisteredHavePolicyListsMissing(t *testing.T) {
	set := buildTestPolicySet(t, map[string][]string{
		"testshop.v1.Shop":  {"Get", "Put"},
		"testshop.v1.Thing": {"Get"},
	})

	// 注册实现漂移：Thing 还注册了 proto 未声明（未注解）的 Put。
	srv := grpc.NewServer()
	registerTestService(srv, "testshop.v1.Shop", "Get", "Put")
	registerTestService(srv, "testshop.v1.Thing", "Get", "Put")

	err := interceptor.AssertAllRegisteredHavePolicy(srv, set)
	if err == nil {
		t.Fatal("expected error for method missing policy")
	}
	if !strings.Contains(err.Error(), "/testshop.v1.Thing/Put") {
		t.Fatalf("error should list the missing method: %v", err)
	}
	if strings.Contains(err.Error(), "/testshop.v1.Shop/") {
		t.Fatalf("covered service should not be listed: %v", err)
	}
}

func TestAssertAllRegisteredHavePolicyPassesWithFrameworkServices(t *testing.T) {
	set := buildTestPolicySet(t, map[string][]string{
		"testshop.v1.Shop":  {"Get", "Put"},
		"testshop.v1.Thing": {"Get"},
	})

	srv := grpc.NewServer()
	registerTestService(srv, "testshop.v1.Shop", "Get", "Put")
	registerTestService(srv, "testshop.v1.Thing", "Get")
	// health/reflection 无业务注解，必须被豁免。
	healthpb.RegisterHealthServer(srv, health.NewServer())
	reflection.Register(srv)

	if err := interceptor.AssertAllRegisteredHavePolicy(srv, set); err != nil {
		t.Fatalf("framework services should be exempt: %v", err)
	}
}

func TestAssertAllRegisteredHavePolicyExemptIsPrefixBased(t *testing.T) {
	// 形似框架但前缀不匹配的服务不受豁免保护（fail-closed）。
	set := buildTestPolicySet(t, map[string][]string{"testshop.v1.Shop": {"Get"}})

	srv := grpc.NewServer()
	registerTestService(srv, "testshop.v1.Shop", "Get")
	registerTestService(srv, "grpc.health.v1.Health", "Check") // 真前缀 → 豁免
	registerTestService(srv, "grpc.health.v2.Health", "Check") // 伪前缀 → 必须报缺失
	registerTestService(srv, "my.grpc.reflection.v1.Mirror", "Bounce")

	err := interceptor.AssertAllRegisteredHavePolicy(srv, set)
	if err == nil {
		t.Fatal("expected error for non-exempt services without policy")
	}
	for _, want := range []string{"/grpc.health.v2.Health/Check", "/my.grpc.reflection.v1.Mirror/Bounce"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error should list %s: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "/grpc.health.v1.Health/Check") {
		t.Fatalf("true framework prefix must stay exempt: %v", err)
	}
}
