package authz_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lynx-go/grpcapi/authz"
	"github.com/lynx-go/grpcapi/policy"
	"github.com/lynx-go/grpcapi/principal"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestHTTPMiddleware(t *testing.T) {
	set := testSet(t, policy.Operation{
		ID: "GET /admin", Kind: policy.KindHTTP, Exposure: policy.ExposureInternal,
		Policy: policy.Policy{Require: []policy.Requirement{{Kind: "role", Values: []string{"admin"}}}},
	})
	decider, err := authz.NewRequirementDecider(set)
	if err != nil {
		t.Fatal(err)
	}
	op, _ := set.Get("GET /admin")

	var written error
	mw := authz.HTTPMiddleware(decider, op, authz.HTTPOptions{
		ErrorWriter: func(w http.ResponseWriter, _ *http.Request, err error) {
			written = err
			w.WriteHeader(499)
		},
	})
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })

	// No principal -> 401.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	mw(next).ServeHTTP(rec, req)
	if code := status.Code(written); code != codes.Unauthenticated {
		t.Fatalf("no principal code = %v, want Unauthenticated", code)
	}

	// User -> 403.
	req = req.WithContext(principal.With(context.Background(), &principal.Principal{ID: "u1", Kind: principal.KindUser}))
	mw(next).ServeHTTP(rec, req)
	if code := status.Code(written); code != codes.PermissionDenied {
		t.Fatalf("user code = %v, want PermissionDenied", code)
	}

	// Admin -> 200.
	req = req.WithContext(principal.With(context.Background(), &principal.Principal{
		ID: "a1", Kind: principal.KindUser, Claims: map[string][]string{"roles": {"admin"}},
	}))
	rec = httptest.NewRecorder()
	mw(next).ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("admin status = %d, want 200", rec.Code)
	}
}

func TestHTTPMiddlewareDefaultErrorWriter(t *testing.T) {
	set := testSet(t, policy.Operation{
		ID: "GET /private", Kind: policy.KindHTTP, Exposure: policy.ExposureInternal,
		Policy: policy.Policy{Anonymous: false, Require: []policy.Requirement{{Kind: "authenticated"}}},
	})
	decider, _ := authz.NewRequirementDecider(set)
	op, _ := set.Get("GET /private")
	rec := httptest.NewRecorder()
	authz.HTTPMiddleware(decider, op, authz.HTTPOptions{})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/private", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}
