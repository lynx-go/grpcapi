package audit_test

import (
	"context"
	"errors"
	"testing"

	"github.com/lynx-go/grpcapi/audit"
	"github.com/lynx-go/grpcapi/contextx"
	"github.com/lynx-go/grpcapi/principal"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func unaryInfo() *grpc.UnaryServerInfo { return &grpc.UnaryServerInfo{FullMethod: "/svc.Notes/Create"} }

func TestAuditCapturesOutcomeAndIdentity(t *testing.T) {
	var events []audit.Event
	a := audit.New(audit.Options{Sink: func(_ context.Context, e audit.Event) { events = append(events, e) }})
	ctx := principal.With(
		contextx.WithClientInfo(context.Background(), contextx.ClientInfo{IP: "203.0.113.9", UserAgent: "cli/1.0"}),
		&principal.Principal{ID: "user-1", Kind: "user"},
	)
	handlerOK := func(context.Context, any) (any, error) { return "ok", nil }
	handlerErr := func(context.Context, any) (any, error) {
		return nil, status.Error(codes.NotFound, "missing")
	}
	if _, err := a.Unary()(ctx, nil, unaryInfo(), handlerOK); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Unary()(ctx, nil, unaryInfo(), handlerErr); err == nil {
		t.Fatal("handler error swallowed")
	}
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2", len(events))
	}
	ok, failed := events[0], events[1]
	if ok.Code != codes.OK || ok.PrincipalID != "user-1" || ok.PrincipalKind != "user" || ok.ClientIP != "203.0.113.9" || ok.UserAgent != "cli/1.0" {
		t.Fatalf("ok event = %+v", ok)
	}
	if failed.Code != codes.NotFound {
		t.Fatalf("failed code = %v, want NotFound", failed.Code)
	}
	if failed.Duration < 0 || ok.Method != "/svc.Notes/Create" {
		t.Fatalf("bad event fields: %+v", failed)
	}
}

func TestAuditAnonymous(t *testing.T) {
	var events []audit.Event
	a := audit.New(audit.Options{Sink: func(_ context.Context, e audit.Event) { events = append(events, e) }})
	_, _ = a.Unary()(context.Background(), nil, unaryInfo(), func(context.Context, any) (any, error) {
		return nil, status.Error(codes.PermissionDenied, "denied")
	})
	if len(events) != 1 || !events[0].Anonymous || events[0].PrincipalID != "" {
		t.Fatalf("event = %+v, want anonymous", events)
	}
}

func TestAuditIncludeFiltersMethods(t *testing.T) {
	var count int
	a := audit.New(audit.Options{
		Sink:    func(context.Context, audit.Event) { count++ },
		Include: func(_ context.Context, method string) bool { return method == "/svc.Notes/Create" },
	})
	_, _ = a.Unary()(context.Background(), nil, unaryInfo(), func(context.Context, any) (any, error) { return nil, nil })
	_, _ = a.Unary()(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/svc.Health/Check"},
		func(context.Context, any) (any, error) { return nil, nil })
	if count != 1 {
		t.Fatalf("audited = %d, want 1 (health filtered)", count)
	}
}

func TestAuditSinkPanicDoesNotFailRequest(t *testing.T) {
	a := audit.New(audit.Options{Sink: func(context.Context, audit.Event) { panic("sink down") }})
	resp, err := a.Unary()(context.Background(), nil, unaryInfo(), func(context.Context, any) (any, error) {
		return "ok", nil
	})
	if err != nil || resp != "ok" {
		t.Fatalf("resp = %v err = %v, want request unaffected by sink panic", resp, err)
	}
	_ = errors.New // 保留 errors 引用
}
