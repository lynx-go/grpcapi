package ticket_test

import (
	"context"
	"testing"

	"github.com/lynx-go/grpcapi/authn"
	"github.com/lynx-go/grpcapi/authn/ticket"
	"github.com/lynx-go/grpcapi/principal"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeStore struct {
	byToken map[string]*principal.Principal
}

func (s *fakeStore) Redeem(_ context.Context, token string) (*principal.Principal, error) {
	if p, ok := s.byToken[token]; ok {
		return p, nil
	}
	return nil, status.Error(codes.Unauthenticated, "ticket unknown or used")
}

func TestAuthenticator(t *testing.T) {
	store := &fakeStore{byToken: map[string]*principal.Principal{
		"valid": {ID: "user-1", Kind: "user"},
	}}
	a := ticket.New(store)

	// 无票据：(nil, nil) 交还链。
	p, err := a.Authenticate(context.Background(), authn.Credentials{})
	if p != nil || err != nil {
		t.Fatalf("empty credentials = %v, %v", p, err)
	}
	// 有效票据兑换。
	p, err = a.Authenticate(context.Background(), authn.Credentials{Tickets: []string{"valid"}})
	if err != nil || p == nil || p.ID != "user-1" {
		t.Fatalf("valid = %v, %v", p, err)
	}
	if a.Name() != "ticket" {
		t.Fatalf("name = %q", a.Name())
	}
	// 已用票据：Store 返回错误 → 认证失败。
	p, err = a.Authenticate(context.Background(), authn.Credentials{Tickets: []string{"used"}})
	if err == nil || p != nil {
		t.Fatalf("used ticket = %v, %v, want error", p, err)
	}
}

func TestNewRequiresStore(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("New(nil) should panic")
		}
	}()
	ticket.New(nil)
}
