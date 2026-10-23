package authn_test

import (
	"context"
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

func TestQueryTicketExtractionOptIn(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/v1/events?ticket=tok-1", nil)
	// 默认提取器不从 query 取凭证。
	c, err := authn.DefaultHTTPExtractor().ExtractHTTP(context.Background(), "/v1/events", r)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Tickets) != 0 || !c.Empty() {
		t.Fatalf("default extractor picked query ticket: %+v", c)
	}
	// 组合提取器取单值。
	c, err = authn.WithQueryTicket("", nil).ExtractHTTP(context.Background(), "/v1/events", r)
	if err != nil {
		t.Fatal(err)
	}
	if c.Ticket() != "tok-1" || c.Empty() {
		t.Fatalf("tickets = %+v", c)
	}
	// 自定义参数名。
	r2 := httptest.NewRequest(http.MethodGet, "/v1/events?st=tok-2", nil)
	c, err = authn.WithQueryTicket("st", nil).ExtractHTTP(context.Background(), "/v1/events", r2)
	if err != nil {
		t.Fatal(err)
	}
	if c.Ticket() != "tok-2" {
		t.Fatalf("tickets = %+v", c)
	}
	// 与 header 凭证组合透传（header 部分仍由默认提取器处理）。
	r3 := httptest.NewRequest(http.MethodGet, "/v1/events?ticket=tok-1", nil)
	r3.Header.Set("X-Api-Key", "key-1")
	c, _ = authn.WithQueryTicket("", nil).ExtractHTTP(context.Background(), "/v1/events", r3)
	if c.APIKey() != "key-1" || c.Ticket() != "tok-1" || c.AuthKinds() != 2 {
		t.Fatalf("combined = %+v kinds=%d", c, c.AuthKinds())
	}
}

func TestQueryTicketRepeatedParamRejected(t *testing.T) {
	i := authn.New(authn.Chain{fakeAuthenticator{name: "tk", fn: func(authn.Credentials) (*principal.Principal, error) {
		return &principal.Principal{ID: "u1"}, nil
	}}}, authn.Options{})
	r := httptest.NewRequest(http.MethodGet, "/v1/events?ticket=a&ticket=b", nil)
	h := i.HTTPMiddleware("/v1/events", authn.HTTPOptions{
		Extractor: authn.WithQueryTicket("", nil),
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401 for repeated ticket param", rec.Code)
	}
}

func TestGRPCMetadataTicket(t *testing.T) {
	md := metadata.Pairs("x-ticket", "tok-9")
	c, err := authn.DefaultExtractor().Extract(context.Background(), "/svc/Get", md, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Ticket() != "tok-9" {
		t.Fatalf("tickets = %+v", c)
	}
}

func TestInvalidCredentialByKind(t *testing.T) {
	// torchwood 形态：public 面无效 Bearer 降级匿名，无效 API key 恒 401。
	authenticator := fakeAuthenticator{name: "reject-all", fn: func(authn.Credentials) (*principal.Principal, error) {
		return nil, status.Error(codes.Unauthenticated, "bad credentials")
	}}
	i := authn.New(authn.Chain{authenticator}, authn.Options{
		InvalidCredentialByKind: map[authn.CredentialKind]authn.InvalidCredentialPolicy{
			authn.KindBearer: authn.InvalidCredentialIgnoreOnAnonymous,
			authn.KindAPIKey: authn.InvalidCredentialReject,
		},
		IsAnonymous: func(string) bool { return true },
	})

	bearer := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer bad"))
	if err := unaryWithCtx(i, bearer); err != nil {
		t.Fatalf("invalid bearer on public should degrade to anonymous: %v", err)
	}

	apikey := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-api-key", "bad"))
	if err := unaryWithCtx(i, apikey); err == nil || status.Code(err) != codes.Unauthenticated {
		t.Fatalf("invalid api key should 401, got %v", err)
	}
}

func unaryWithCtx(i *authn.Interceptor, ctx context.Context) error {
	info := &grpc.UnaryServerInfo{FullMethod: "/svc/Public/Get"}
	_, err := i.Unary()(ctx, nil, info, func(context.Context, any) (any, error) { return "ok", nil })
	return err
}

func TestInvalidCredentialByKindFailClosedOnMixedDefaults(t *testing.T) {
	// 覆盖项缺失时回落全局默认 Reject——即使另一族配置了 Ignore。
	authenticator := fakeAuthenticator{name: "reject-all", fn: func(authn.Credentials) (*principal.Principal, error) {
		return nil, status.Error(codes.Unauthenticated, "bad")
	}}
	i := authn.New(authn.Chain{authenticator}, authn.Options{
		InvalidCredentialPolicy: authn.InvalidCredentialReject,
		InvalidCredentialByKind: map[authn.CredentialKind]authn.InvalidCredentialPolicy{
			authn.KindBearer: authn.InvalidCredentialIgnoreOnAnonymous,
		},
		IsAnonymous: func(string) bool { return true },
	})
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-api-key", "bad"))
	if err := unaryWithCtx(i, ctx); err == nil {
		t.Fatal("api key should fall back to global Reject")
	}
}
