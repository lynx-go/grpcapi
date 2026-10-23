package scope_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lynx-go/grpcapi/example/echo/v1"
	"github.com/lynx-go/grpcapi/policy"
	"github.com/lynx-go/grpcapi/policy/scope"
	"github.com/lynx-go/grpcapi/principal"
)

func TestGrantsInstance(t *testing.T) {
	set := scope.Set{"databases", "notes:read", "notes:blog", "cache:*"}
	cases := []struct {
		resource, target string
		want             bool
	}{
		{"databases", "blog", true}, // 资源整体授权
		{"notes", "blog", true},     // 实例级授权 notes:blog
		{"notes", "wiki", false},    // 只授权了 blog
		{"notes", "read", false},    // 实例 ID 与 op 同名按 op 解释（不授予）
		{"cache", "anything", true}, // 显式实例通配
		{"other", "x", false},
	}
	for _, tc := range cases {
		if got := scope.GrantsInstance(set, tc.resource, tc.target, true); got != tc.want {
			t.Errorf("GrantsInstance(%q,%q) = %v, want %v", tc.resource, tc.target, got, tc.want)
		}
	}
	if scope.GrantsInstance(scope.Set{"*"}, "any", "x", true) != true {
		t.Error("global wildcard should grant")
	}
	if scope.GrantsInstance(scope.Set{"*"}, "any", "x", false) != false {
		t.Error("wildcard must be ignored when disallowed")
	}
}

// resourceKind 是被测 kind 的固定装配（FieldID 提取 echo 请求字段）。
func resourceKind(t *testing.T) policy.RequirementKind {
	t.Helper()
	k, err := scope.ResourceKind(scope.ResourceOptions{
		ID: scope.FieldID("filter", "text"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestResourceKindRequiresExtractor(t *testing.T) {
	if _, err := scope.ResourceKind(scope.ResourceOptions{}); err == nil {
		t.Fatal("want error for missing ID extractor")
	}
}

func TestResourceKindValidate(t *testing.T) {
	k := resourceKind(t)
	vocab := policy.NewVocabulary(map[string][]string{"resource": {"databases"}})
	bad := []policy.Requirement{
		{Kind: "resource"},
		{Kind: "resource", Values: []string{"databases", "notes"}},
		{Kind: "resource", Values: []string{"*"}},
		// 声明值携带非 op 后缀 = 实例寻址，属 principal 授权面，不属声明面。
		{Kind: "resource", Values: []string{"databases:blog"}},
		{Kind: "resource", Values: []string{"databases:"}},
		{Kind: "resource", Values: []string{"databases:create"}},
	}
	for _, req := range bad {
		if err := k.Validate(req, vocab); err == nil {
			t.Errorf("Validate(%+v) should fail", req)
		}
	}
	for _, value := range []string{"databases", "databases:read", "databases:write", "databases:admin"} {
		if err := k.Validate(policy.Requirement{Kind: "resource", Values: []string{value}}, vocab); err != nil {
			t.Fatalf("valid requirement %q rejected: %v", value, err)
		}
	}
}

func TestResourceKindEvaluate(t *testing.T) {
	k := resourceKind(t)
	req := policy.Requirement{Kind: "resource", Values: []string{"notes"}}
	request := &echov1.HearRequest{Filter: "blog"}

	eval := func(p *principal.Principal, reqAny any) (bool, error) {
		return k.Evaluate(context.Background(), policy.EvalContext{Principal: p, Request: reqAny}, req)
	}

	// 无 principal → 拒绝。
	if ok, err := eval(nil, request); ok || err != nil {
		t.Fatalf("no principal = %v, %v; want false, nil", ok, err)
	}
	// 资源整体授权。
	pAll := &principal.Principal{Claims: map[string][]string{"scopes": {"notes"}}}
	if ok, _ := eval(pAll, request); !ok {
		t.Fatal("resource-wide grant should allow")
	}
	// 实例级授权：寻址 blog 放行。
	pBlog := &principal.Principal{Claims: map[string][]string{"scopes": {"notes:blog"}}}
	if ok, _ := eval(pBlog, request); !ok {
		t.Fatal("instance grant notes:blog should allow target blog")
	}
	// 寻址其他实例拒绝。
	pOther := &principal.Principal{Claims: map[string][]string{"scopes": {"notes:wiki"}}}
	if ok, _ := eval(pOther, request); ok {
		t.Fatal("instance grant notes:wiki must not allow target blog")
	}
	// 操作级 token 不授予实例寻址。
	pOp := &principal.Principal{Claims: map[string][]string{"scopes": {"notes:read"}}}
	if ok, _ := eval(pOp, request); ok {
		t.Fatal("op-level grant must not satisfy instance gate")
	}
	// 无方向声明（"notes"）：实例+方向单 token 不剥后缀，不授予（兼容不变量）。
	pBlogRead := &principal.Principal{Claims: map[string][]string{"scopes": {"notes:blog.read"}}}
	if ok, _ := eval(pBlogRead, request); ok {
		t.Fatal("op-less gate must not strip instance op suffix")
	}
}

// TestResourceKindEvaluateOpAware：方向感知实例门（声明值 "notes:read"）——
// torchwood T-02「单 token = 方向 + 实例」合取语义（G-1 修复）。
func TestResourceKindEvaluateOpAware(t *testing.T) {
	k := resourceKind(t)
	req := policy.Requirement{Kind: "resource", Values: []string{"notes:read"}}
	request := &echov1.HearRequest{Filter: "blog"}

	eval := func(scopes ...string) (bool, error) {
		p := &principal.Principal{Claims: map[string][]string{"scopes": scopes}}
		return k.Evaluate(context.Background(), policy.EvalContext{Principal: p, Request: request}, req)
	}

	cases := []struct {
		name   string
		scopes []string
		want   bool
	}{
		{"实例+方向单 token,方向一致", []string{"notes:blog.read"}, true},
		{"实例+方向单 token,方向不一致", []string{"notes:blog.write"}, false},
		{"无后缀实例 token = 全方向", []string{"notes:blog"}, true},
		{"实例+方向 token,其他实例", []string{"notes:wiki.read"}, false},
		{"操作级 token 不授予实例", []string{"notes:read"}, false},
		{"资源整体授权", []string{"notes"}, true},
		{"通配符", []string{"*"}, true},
	}
	for _, tc := range cases {
		if got, err := eval(tc.scopes...); got != tc.want || err != nil {
			t.Errorf("%s: got %v, %v; want %v, nil", tc.name, got, err, tc.want)
		}
	}
}

// TestGrantsInstanceFor：方向感知实例判定的纯函数面。每个用例独立 scope
// 集，避免多 token 叠加干扰；instWant 是 GrantsInstance（op="" 委托路径）
// 的期望——兼容不变量：op 为空不剥实例段方向后缀。
func TestGrantsInstanceFor(t *testing.T) {
	cases := []struct {
		name                 string
		set                  scope.Set
		resource, target, op string
		forWant, instWant    bool
	}{
		{"实例+方向单 token,方向一致", scope.Set{"notes:blog.read"}, "notes", "blog", "read", true, false},
		{"实例+方向单 token,方向不一致", scope.Set{"notes:blog.read"}, "notes", "blog", "write", false, false},
		{"实例+方向单 token,其他实例", scope.Set{"notes:blog.read"}, "notes", "wiki", "read", false, false},
		{"无后缀实例 token = 全方向", scope.Set{"notes:blog"}, "notes", "blog", "write", true, true},
		{"操作级 token 不授予实例", scope.Set{"notes:read"}, "notes", "read", "read", false, false},
		{"资源整体授权覆盖任意方向", scope.Set{"databases"}, "databases", "any", "write", true, true},
		{"显式实例通配", scope.Set{"cache:*"}, "cache", "anything", "read", true, true},
		{"全局通配", scope.Set{"*"}, "any", "x", "write", true, true},
	}
	for _, tc := range cases {
		if got := scope.GrantsInstanceFor(tc.set, tc.resource, tc.target, tc.op, true); got != tc.forWant {
			t.Errorf("%s: GrantsInstanceFor(%s,%s,%s) = %v, want %v", tc.name, tc.resource, tc.target, tc.op, got, tc.forWant)
		}
		if got := scope.GrantsInstance(tc.set, tc.resource, tc.target, true); got != tc.instWant {
			t.Errorf("%s: GrantsInstance(%s,%s) = %v, want %v（op 为空不剥实例段后缀）", tc.name, tc.resource, tc.target, got, tc.instWant)
		}
	}
}

func TestResourceKindEvaluateFailClosed(t *testing.T) {
	k := resourceKind(t)
	req := policy.Requirement{Kind: "resource", Values: []string{"notes"}}
	p := &principal.Principal{Claims: map[string][]string{"scopes": {"notes"}}}

	// 请求缺少可提取目标 → 求值错误（Internal），不放行。
	if _, err := k.Evaluate(context.Background(), policy.EvalContext{Principal: p, Request: &echov1.HearRequest{}}, req); err == nil {
		t.Fatal("missing target id should error")
	}
	// 不支持的请求类型 → 错误。
	if _, err := k.Evaluate(context.Background(), policy.EvalContext{Principal: p, Request: "bogus"}, req); err == nil {
		t.Fatal("unsupported request type should error")
	}
}

func TestResourceKindHTTPExtraction(t *testing.T) {
	k, err := scope.ResourceKind(scope.ResourceOptions{ID: scope.PathID("id")})
	if err != nil {
		t.Fatal(err)
	}
	req := policy.Requirement{Kind: "resource", Values: []string{"databases"}}
	p := &principal.Principal{Claims: map[string][]string{"scopes": {"databases:db1"}}}

	r := httptest.NewRequest(http.MethodGet, "/v1/databases/db1", nil)
	r.SetPathValue("id", "db1")
	if ok, err := k.Evaluate(context.Background(), policy.EvalContext{Principal: p, Request: r}, req); err != nil || !ok {
		t.Fatalf("path extraction = %v, %v; want true", ok, err)
	}

	r2 := httptest.NewRequest(http.MethodGet, "/v1/databases", nil)
	if _, err := k.Evaluate(context.Background(), policy.EvalContext{Principal: p, Request: r2}, req); err == nil {
		t.Fatal("missing path value should error")
	}

	kq, err := scope.ResourceKind(scope.ResourceOptions{ID: scope.QueryID("database")})
	if err != nil {
		t.Fatal(err)
	}
	r3 := httptest.NewRequest(http.MethodGet, "/v1/databases?database=db1", nil)
	if ok, err := kq.Evaluate(context.Background(), policy.EvalContext{Principal: p, Request: r3}, req); err != nil || !ok {
		t.Fatalf("query extraction = %v, %v; want true", ok, err)
	}
}
