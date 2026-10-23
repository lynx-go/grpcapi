package interceptor_test

import (
	"context"
	"strings"
	"testing"

	"github.com/lynx-go/grpcapi/interceptor"
	"google.golang.org/grpc"
)

// TestReservedStageConstructors 钉住预留槽位构造器（RateLimit/Audit/Usage）：
// GENERALIZATION 把审计/限流实现列为"后置"，构造器是链架构的既有槽位——
// 本测试保证它们在被真实实现消费前，名字/顺序/透传行为不漂移。
func TestReservedStageConstructors(t *testing.T) {
	pass := func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		return handler(ctx, req)
	}
	passStream := func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return handler(srv, ss)
	}

	cases := []struct {
		name  string
		stage interceptor.Stage
		want  string
		order int
	}{
		{"ratelimit", interceptor.RateLimitStage(pass, passStream), interceptor.StageRateLimit, interceptor.OrderRateLimit},
		{"audit", interceptor.AuditStage(pass, passStream), interceptor.StageAudit, interceptor.OrderAudit},
		{"usage", interceptor.UsageStage(pass, passStream), interceptor.StageUsage, interceptor.OrderUsage},
	}
	for _, tc := range cases {
		if tc.stage.Name != tc.want || tc.stage.Order != tc.order {
			t.Errorf("%s: name/order = %q/%d, want %q/%d", tc.name, tc.stage.Name, tc.stage.Order, tc.want, tc.order)
		}
		if tc.stage.Unary == nil || tc.stage.Stream == nil {
			t.Errorf("%s: unary/stream interceptor must be wired", tc.name)
		}
	}

	// 三槽位可组链且按 Order 升序执行（40 → 50 → 60）。
	var calls []string
	recording := func(name string) grpc.UnaryServerInterceptor {
		return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			calls = append(calls, name)
			return handler(ctx, req)
		}
	}
	chain, err := interceptor.Assemble(
		interceptor.RateLimitStage(recording("ratelimit"), passStream),
		interceptor.AuditStage(recording("audit"), passStream),
		interceptor.UsageStage(recording("usage"), passStream),
	)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	// Chain.Unary() 返回拦截器切片，手工折叠成可调用的 handler。
	list := chain.Unary()
	info := &grpc.UnaryServerInfo{FullMethod: "/t/S/M"}
	handler := func(ctx context.Context, _ any) (any, error) { return "ok", nil }
	for i := len(list) - 1; i >= 0; i-- {
		ic, next := list[i], handler
		handler = func(ctx context.Context, req any) (any, error) {
			return ic(ctx, req, info, next)
		}
	}
	if _, err := handler(context.Background(), nil); err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if got, want := strings.Join(calls, ","), "ratelimit,audit,usage"; got != want {
		t.Fatalf("execution order = %q, want %q", got, want)
	}
}
