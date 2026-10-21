package authn_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lynx-go/grpcapi/authn"
	"github.com/lynx-go/grpcapi/principal"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type fakeAuthenticator struct {
	name string
	fn   func(authn.Credentials) (*principal.Principal, error)
}

func (f fakeAuthenticator) Name() string { return f.name }
func (f fakeAuthenticator) Authenticate(_ context.Context, c authn.Credentials) (*principal.Principal, error) {
	return f.fn(c)
}

func TestExtractor(t *testing.T) {
	md := metadata.Pairs(
		"authorization", "Bearer tok-1",
		"x-api-key", "key-1",
		"cookie", "session=abc; csrf=def",
	)
	c, err := authn.DefaultExtractor().Extract(context.Background(), "/svc/Get", md, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.BearerToken() != "tok-1" || c.APIKey() != "key-1" {
		t.Fatalf("credentials = %+v", c)
	}
	if c.Cookie("session") != "abc" || c.Cookie("csrf") != "def" {
		t.Fatalf("cookies = %+v", c)
	}
	if c.AuthKinds() != 3 || c.Empty() {
		t.Fatalf("kinds = %d, empty=%v", c.AuthKinds(), c.Empty())
	}
}

func TestChainOrder(t *testing.T) {
	first := fakeAuthenticator{name: "first", fn: func(authn.Credentials) (*principal.Principal, error) { return nil, nil }}
	second := fakeAuthenticator{name: "second", fn: func(authn.Credentials) (*principal.Principal, error) {
		return &principal.Principal{ID: "u1"}, nil
	}}
	p, err := authn.Chain{first, second}.Authenticate(context.Background(), authn.Credentials{Bearer: []string{"x"}})
	if err != nil || p == nil || p.ID != "u1" {
		t.Fatalf("Authenticate = %+v, %v", p, err)
	}

	third := fakeAuthenticator{name: "third", fn: func(authn.Credentials) (*principal.Principal, error) {
		return nil, status.Error(codes.Unavailable, "jwks down")
	}}
	_, err = authn.Chain{first, third}.Authenticate(context.Background(), authn.Credentials{Bearer: []string{"x"}})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", status.Code(err))
	}
}

func TestUnaryInterceptor(t *testing.T) {
	auth := fakeAuthenticator{name: "fake", fn: func(c authn.Credentials) (*principal.Principal, error) {
		if c.BearerToken() == "good" {
			return &principal.Principal{ID: "u1", Kind: principal.KindUser}, nil
		}
		return nil, status.Error(codes.Unauthenticated, "bad token")
	}}
	i := authn.New(authn.Chain{auth}, authn.Options{})
	ic := i.Unary()
	info := &grpc.UnaryServerInfo{FullMethod: "/svc/Get"}

	var got *principal.Principal
	handler := func(ctx context.Context, _ any) (any, error) {
		got, _ = principal.From(ctx)
		return "ok", nil
	}

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer good"))
	if _, err := ic(ctx, nil, info, handler); err != nil {
		t.Fatalf("valid: %v", err)
	}
	if got == nil || got.ID != "u1" {
		t.Fatalf("principal = %+v", got)
	}

	got = nil
	ctx = metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer bad"))
	_, err := ic(ctx, nil, info, handler)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", status.Code(err))
	}
	if got != nil {
		t.Fatal("handler should not run with invalid credentials")
	}

	// 无凭证：放行，由 authz 决定。
	got = nil
	if _, err := ic(context.Background(), nil, info, handler); err != nil {
		t.Fatalf("no credentials: %v", err)
	}
	if got != nil {
		t.Fatal("no-credential request should have no principal")
	}
}

func TestUnaryMultipleCredentialsRejected(t *testing.T) {
	auth := fakeAuthenticator{name: "fake", fn: func(authn.Credentials) (*principal.Principal, error) {
		return &principal.Principal{ID: "u1"}, nil
	}}
	ic := authn.New(authn.Chain{auth}, authn.Options{}).Unary()
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"authorization", "Bearer tok",
		"x-api-key", "key",
	))
	_, err := ic(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/svc/Get"},
		func(context.Context, any) (any, error) { return nil, nil })
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", status.Code(err))
	}
}

func TestUnaryRejectsDuplicateBearer(t *testing.T) {
	auth := fakeAuthenticator{name: "fake", fn: func(authn.Credentials) (*principal.Principal, error) {
		return &principal.Principal{ID: "u1"}, nil
	}}
	ic := authn.New(authn.Chain{auth}, authn.Options{}).Unary()
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"authorization", "Bearer first",
		"authorization", "Bearer second",
	))
	_, err := ic(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/svc/Get"},
		func(context.Context, any) (any, error) { return nil, nil })
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", status.Code(err))
	}
}

func TestCredentialsMTLS(t *testing.T) {
	c := authn.Credentials{TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}}
	if c.Empty() {
		t.Fatal("mTLS credentials must not be empty")
	}
	if c.AuthKinds() != 1 {
		t.Fatalf("AuthKinds = %d, want 1", c.AuthKinds())
	}
}

func TestUnaryIgnoreInvalidOnAnonymous(t *testing.T) {
	auth := fakeAuthenticator{name: "fake", fn: func(authn.Credentials) (*principal.Principal, error) {
		return nil, status.Error(codes.Unauthenticated, "bad")
	}}
	ic := authn.New(authn.Chain{auth}, authn.Options{
		InvalidCredentialPolicy: authn.InvalidCredentialIgnoreOnAnonymous,
		IsAnonymous:             func(string) bool { return true },
	}).Unary()
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer bad"))
	called := false
	_, err := ic(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/svc/Public"},
		func(context.Context, any) (any, error) { called = true; return nil, nil })
	if err != nil || !called {
		t.Fatalf("err = %v, called=%v", err, called)
	}
}

func TestHTTPMiddleware(t *testing.T) {
	auth := fakeAuthenticator{name: "fake", fn: func(c authn.Credentials) (*principal.Principal, error) {
		if c.BearerToken() == "good" {
			return &principal.Principal{ID: "u1"}, nil
		}
		return nil, status.Error(codes.Unauthenticated, "bad")
	}}
	i := authn.New(authn.Chain{auth}, authn.Options{})
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := principal.From(r.Context())
		if p == nil {
			t.Fatal("principal missing in handler")
		}
		w.WriteHeader(200)
	})

	req := httptest.NewRequest(http.MethodGet, "/route", nil)
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	i.HTTPMiddleware("GET /route", authn.HTTPOptions{})(next).ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/route", nil)
	req.Header.Set("Authorization", "Bearer bad")
	rec = httptest.NewRecorder()
	i.HTTPMiddleware("GET /route", authn.HTTPOptions{})(next).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/route", nil)
	req.Header.Add("Authorization", "Bearer first")
	req.Header.Add("Authorization", "Bearer second")
	rec = httptest.NewRecorder()
	i.HTTPMiddleware("GET /route", authn.HTTPOptions{})(next).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("duplicate bearer status = %d, want 401", rec.Code)
	}
}
