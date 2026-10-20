package authz_test

import (
	"context"
	"io"
	"testing"

	"github.com/lynx-go/grpcapi/authz"
	"github.com/lynx-go/grpcapi/policy"
	"github.com/lynx-go/grpcapi/principal"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type fakeStream struct {
	ctx     context.Context
	msgs    []any
	idx     int
	sent    []any
	recvErr error
}

func (s *fakeStream) Context() context.Context     { return s.ctx }
func (s *fakeStream) SetHeader(metadata.MD) error  { return nil }
func (s *fakeStream) SendHeader(metadata.MD) error { return nil }
func (s *fakeStream) SetTrailer(metadata.MD)       {}
func (s *fakeStream) SendMsg(m any) error          { s.sent = append(s.sent, m); return nil }
func (s *fakeStream) RecvMsg(any) error {
	if s.recvErr != nil {
		return s.recvErr
	}
	if s.idx >= len(s.msgs) {
		return io.EOF
	}
	s.idx++
	return nil
}

func TestUnaryInterceptor(t *testing.T) {
	set := testSet(t,
		op("/svc/Public", policy.Policy{Anonymous: true}),
		op("/svc/Denied", policy.Policy{Require: []policy.Requirement{{Kind: "role", Values: []string{"admin"}}}}),
	)
	i, err := authz.NewInterceptor(set, nil, authz.InterceptorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	interceptor := i.Unary()

	called := false
	handler := func(context.Context, any) (any, error) {
		called = true
		return "ok", nil
	}
	info := func(id string) *grpc.UnaryServerInfo { return &grpc.UnaryServerInfo{FullMethod: id} }

	if _, err := interceptor(context.Background(), nil, info("/svc/Public"), handler); err != nil {
		t.Fatalf("public: %v", err)
	}
	if !called {
		t.Fatal("public handler not called")
	}

	called = false
	_, err = interceptor(context.Background(), nil, info("/svc/Denied"), handler)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("missing principal code = %v, want Unauthenticated", status.Code(err))
	}
	if called {
		t.Fatal("denied handler should not be called")
	}

	userCtx := principal.With(context.Background(), &principal.Principal{ID: "u1", Kind: principal.KindUser})
	_, err = interceptor(userCtx, nil, info("/svc/Denied"), handler)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("user code = %v, want PermissionDenied", status.Code(err))
	}

	adminCtx := principal.With(context.Background(), &principal.Principal{
		ID: "a1", Kind: principal.KindUser, Claims: map[string][]string{"roles": {"admin"}},
	})
	if _, err := interceptor(adminCtx, nil, info("/svc/Denied"), handler); err != nil {
		t.Fatalf("admin: %v", err)
	}

	_, err = interceptor(context.Background(), nil, info("/svc/Missing"), handler)
	if status.Code(err) != codes.Internal {
		t.Fatalf("missing policy code = %v, want Internal", status.Code(err))
	}
}

func TestStreamInterceptorOpen(t *testing.T) {
	set := testSet(t, policy.Operation{
		ID: "/svc/Stream", Kind: policy.KindGRPC, Exposure: policy.ExposureInternal,
		Streaming: true, StreamAuth: policy.StreamAuthOpen,
		Policy: policy.Policy{Require: []policy.Requirement{{Kind: "role", Values: []string{"admin"}}}},
	})
	i, err := authz.NewInterceptor(set, nil, authz.InterceptorOptions{})
	if err != nil {
		t.Fatal(err)
	}

	called := false
	handler := func(any, grpc.ServerStream) error {
		called = true
		return nil
	}
	info := &grpc.StreamServerInfo{FullMethod: "/svc/Stream"}

	err = i.Stream()(nil, &fakeStream{ctx: context.Background()}, info, handler)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", status.Code(err))
	}
	if called {
		t.Fatal("handler should not be called")
	}

	adminCtx := principal.With(context.Background(), &principal.Principal{
		ID: "a1", Kind: principal.KindUser, Claims: map[string][]string{"roles": {"admin"}},
	})
	if err := i.Stream()(nil, &fakeStream{ctx: adminCtx}, info, handler); err != nil {
		t.Fatalf("admin stream: %v", err)
	}
	if !called {
		t.Fatal("admin handler not called")
	}
}

func TestStreamInterceptorPerMessage(t *testing.T) {
	set := testSet(t, policy.Operation{
		ID: "/svc/Stream", Kind: policy.KindGRPC, Exposure: policy.ExposureInternal,
		Streaming: true, StreamAuth: policy.StreamAuthPerMessage,
		Policy: policy.Policy{Require: []policy.Requirement{{Kind: "role", Values: []string{"admin"}}}},
	})
	i, err := authz.NewInterceptor(set, nil, authz.InterceptorOptions{})
	if err != nil {
		t.Fatal(err)
	}

	handler := func(_ any, ss grpc.ServerStream) error {
		var msg any
		return ss.RecvMsg(&msg)
	}
	info := &grpc.StreamServerInfo{FullMethod: "/svc/Stream"}

	err = i.Stream()(nil, &fakeStream{ctx: context.Background(), msgs: []any{1}}, info, handler)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", status.Code(err))
	}

	adminCtx := principal.With(context.Background(), &principal.Principal{
		ID: "a1", Kind: principal.KindUser, Claims: map[string][]string{"roles": {"admin"}},
	})
	if err := i.Stream()(nil, &fakeStream{ctx: adminCtx, msgs: []any{1}}, info, handler); err != nil {
		t.Fatalf("admin per-message stream: %v", err)
	}
}

func TestInterceptorOnDecision(t *testing.T) {
	set := testSet(t, op("/svc/Public", policy.Policy{Anonymous: true}))
	var decisions []authz.Decision
	i, err := authz.NewInterceptor(set, nil, authz.InterceptorOptions{
		OnDecision: func(_ context.Context, _ policy.Operation, d authz.Decision) {
			decisions = append(decisions, d)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = i.Unary()(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/svc/Public"},
		func(context.Context, any) (any, error) { return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(decisions) != 1 || !decisions[0].Allow {
		t.Fatalf("decisions = %+v", decisions)
	}
}
