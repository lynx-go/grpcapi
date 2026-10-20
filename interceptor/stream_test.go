package interceptor_test

import (
	"context"
	"io"
	"net"
	"testing"

	"github.com/lynx-go/grpcapi/contextx"
	"github.com/lynx-go/grpcapi/interceptor"
	testvalidatev1 "github.com/lynx-go/grpcapi/interceptor/testdata/gen/testvalidate/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type fakeServerStream struct {
	ctx     context.Context
	msgs    []proto.Message
	idx     int
	headers []metadata.MD
}

func (s *fakeServerStream) Context() context.Context { return s.ctx }
func (s *fakeServerStream) SetHeader(md metadata.MD) error {
	s.headers = append(s.headers, md)
	return nil
}
func (s *fakeServerStream) SendHeader(md metadata.MD) error {
	s.headers = append(s.headers, md)
	return nil
}
func (s *fakeServerStream) SetTrailer(metadata.MD) {}
func (s *fakeServerStream) SendMsg(any) error      { return nil }
func (s *fakeServerStream) RecvMsg(m any) error {
	if s.idx >= len(s.msgs) {
		return io.EOF
	}
	dst, ok := m.(proto.Message)
	if !ok {
		return io.ErrUnexpectedEOF
	}
	proto.Merge(dst, s.msgs[s.idx])
	s.idx++
	return nil
}

func TestValidateStreamRejectsInvalidMessage(t *testing.T) {
	ic := interceptor.NewValidate().Stream()
	ss := &fakeServerStream{
		ctx:  context.Background(),
		msgs: []proto.Message{&testvalidatev1.EchoRequest{Name: "ABC", Count: -1}},
	}
	err := ic(nil, ss, &grpc.StreamServerInfo{FullMethod: "/testvalidate.v1.Echo/Stream"}, func(_ any, ss grpc.ServerStream) error {
		var msg testvalidatev1.EchoRequest
		return ss.RecvMsg(&msg)
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument (err = %v)", status.Code(err), err)
	}
}

func TestValidateStreamPassesValidMessage(t *testing.T) {
	ic := interceptor.NewValidate().Stream()
	ss := &fakeServerStream{
		ctx:  context.Background(),
		msgs: []proto.Message{&testvalidatev1.EchoRequest{Id: "abc", Name: "hello", Count: 3}},
	}
	err := ic(nil, ss, &grpc.StreamServerInfo{FullMethod: "/testvalidate.v1.Echo/Stream"}, func(_ any, ss grpc.ServerStream) error {
		var msg testvalidatev1.EchoRequest
		return ss.RecvMsg(&msg)
	})
	if err != nil {
		t.Fatalf("valid stream message rejected: %v", err)
	}
}

func TestClientInfoStream(t *testing.T) {
	ic := interceptor.NewClientInfo(interceptor.ClientInfoConfig{
		TrustedProxies: []string{"10.0.0.0/8"},
	}).Stream()
	ctx := metadata.NewIncomingContext(
		peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1000}}),
		metadata.Pairs("x-forwarded-for", "203.0.113.7"),
	)
	ss := &fakeServerStream{ctx: ctx}
	var got contextx.ClientInfo
	err := ic(nil, ss, &grpc.StreamServerInfo{FullMethod: "/t.v1.Svc/Stream"}, func(_ any, ss grpc.ServerStream) error {
		got, _ = contextx.ClientInfoFrom(ss.Context())
		return nil
	})
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	if got.IP != "203.0.113.7" {
		t.Fatalf("IP = %q, want 203.0.113.7", got.IP)
	}
}

func TestRequestIDStream(t *testing.T) {
	ic := interceptor.NewRequestID(interceptor.RequestIDOptions{
		Generator: func() string { return "generated" },
	}).Stream()
	ss := &fakeServerStream{ctx: metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-request-id", "req-1"))}
	var got string
	err := ic(nil, ss, &grpc.StreamServerInfo{FullMethod: "/t.v1.Svc/Stream"}, func(_ any, ss grpc.ServerStream) error {
		got, _ = contextx.RequestIDFrom(ss.Context())
		return nil
	})
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	if got != "req-1" {
		t.Fatalf("request id = %q, want req-1", got)
	}
	if len(ss.headers) == 0 || ss.headers[0].Get("x-request-id")[0] != "req-1" {
		t.Fatalf("response header missing: %+v", ss.headers)
	}
}

func TestRecoveryStream(t *testing.T) {
	ic := interceptor.NewRecovery(interceptor.RecoveryOptions{}).Stream()
	err := ic(nil, &fakeServerStream{ctx: context.Background()}, &grpc.StreamServerInfo{FullMethod: "/t.v1.Svc/Stream"}, func(any, grpc.ServerStream) error {
		panic("boom")
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("code = %v, want Internal", status.Code(err))
	}
}
