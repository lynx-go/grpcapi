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

func TestHTTPMiddlewareFor(t *testing.T) {
	set := testSet(t,
		op("/svc/Public", policy.Policy{Anonymous: true}),
		op("/svc/Admin", policy.Policy{Require: []policy.Requirement{{Kind: "role", Values: []string{"admin"}}}}),
	)
	d, err := authz.NewRequirementDecider(set)
	if err != nil {
		t.Fatal(err)
	}
	// resolver 按路径路由到 operation——第三方 router 的挂载形态。
	// principal 包提供 With 构造带身份的 ctx。
	resolve := func(r *http.Request) (policy.Operation, bool) {
		switch r.URL.Path {
		case "/public":
			return op("/svc/Public", policy.Policy{Anonymous: true}), true
		case "/admin":
			return op("/svc/Admin", policy.Policy{Require: []policy.Requirement{{Kind: "role", Values: []string{"admin"}}}}), true
		}
		return policy.Operation{}, false
	}
	h := authz.HTTPMiddlewareFor(set, d, resolve, authz.HTTPOptions{})

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	do := func(path string, p *principal.Principal) int {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if p != nil {
			req = req.WithContext(principal.With(req.Context(), p))
		}
		rec := httptest.NewRecorder()
		h(next).ServeHTTP(rec, req)
		return rec.Code
	}

	if got := do("/public", nil); got != http.StatusOK {
		t.Fatalf("public = %d, want 200", got)
	}
	if got := do("/admin", nil); got != http.StatusUnauthorized {
		t.Fatalf("admin no principal = %d, want 401", got)
	}
	user := &principal.Principal{ID: "u1", Claims: map[string][]string{"roles": {"viewer"}}}
	if got := do("/admin", user); got != http.StatusForbidden {
		t.Fatalf("admin viewer = %d, want 403", got)
	}
	admin := &principal.Principal{ID: "a1", Claims: map[string][]string{"roles": {"admin"}}}
	if got := do("/admin", admin); got != http.StatusOK {
		t.Fatalf("admin role = %d, want 200", got)
	}
	// 未注册路径：resolver 未命中 → Internal（fail-closed，不放行）。
	if got := do("/unknown", admin); got != http.StatusInternalServerError {
		t.Fatalf("unknown route = %d, want 500", got)
	}
}
