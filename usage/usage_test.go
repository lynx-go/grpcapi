package usage_test

import (
	"context"
	"testing"

	"github.com/lynx-go/grpcapi/usage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestUsageCountsPerMethod(t *testing.T) {
	m := usage.New()
	info := &grpc.UnaryServerInfo{FullMethod: "/svc.Notes/Create"}
	ok := func(context.Context, any) (any, error) { return "ok", nil }
	fail := func(context.Context, any) (any, error) {
		return nil, status.Error(codes.InvalidArgument, "bad")
	}
	for i := 0; i < 3; i++ {
		if _, err := m.Unary()(context.Background(), nil, info, ok); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.Unary()(context.Background(), nil, info, fail); err == nil {
		t.Fatal("handler error swallowed")
	}
	if _, err := m.Unary()(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/svc.Health/Check"}, ok); err != nil {
		t.Fatal(err)
	}
	snap := m.Snapshot()
	if snap["/svc.Notes/Create"] != (usage.Counters{Requests: 4, Errors: 1}) {
		t.Fatalf("notes counters = %+v", snap["/svc.Notes/Create"])
	}
	if snap["/svc.Health/Check"] != (usage.Counters{Requests: 1, Errors: 0}) {
		t.Fatalf("health counters = %+v", snap["/svc.Health/Check"])
	}
	// Snapshot 是拷贝：外部修改不影响内部计数。
	snap["/svc.Notes/Create"] = usage.Counters{}
	if m.Snapshot()["/svc.Notes/Create"].Requests != 4 {
		t.Fatal("snapshot not a deep copy")
	}
}

func TestUsageSnapshotAndReset(t *testing.T) {
	m := usage.New()
	info := &grpc.UnaryServerInfo{FullMethod: "/svc.Notes/Get"}
	_, _ = m.Unary()(context.Background(), nil, info, func(context.Context, any) (any, error) { return nil, nil })
	got := m.SnapshotAndReset()
	if got["/svc.Notes/Get"].Requests != 1 {
		t.Fatalf("snapshot = %+v", got)
	}
	if again := m.SnapshotAndReset(); len(again) != 0 {
		t.Fatalf("after reset = %+v, want empty", again)
	}
}
