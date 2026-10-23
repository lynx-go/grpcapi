package authz_test

// 本文件是 GENERALIZATION §11.3「复合门官方范式」的执行侧闭环证明：
// torchwood SERVER 档（admin 角色 ∪ API key scope 的 any_of）叠加 v3 新增的
// 资源实例寻址门，完全用库内 kind（claim/scope/resource）表达，并由库的
// RequirementDecider + gRPC 拦截器执行——策略声明与策略执行都在库内闭环，
// 不再需要项目自写执行器（legacy 双投影的终点形态）。
//
// SERVER 档在 v3 的等价表达（MIGRATION §2.2 expandAccess 的运行期验证）：
//
//	policy = {
//	  any_of: [
//	    [ {kind: "admin_role", values: ["ops"]} ],                         // admin 路径
//	    [ {kind: "scope", values: ["databases:read"]},                     // api key 路径：
//	      {kind: "resource", values: ["databases"]} ],                      // 组内 AND = 门叠加
//	  ],
//	}
//
// 组内 AND 是关键：实例寻址门只约束 api key 路径，admin 角色路径不受实例门
// 约束（torchwood 语义原样落地）。

import (
	"context"
	"testing"

	"github.com/lynx-go/grpcapi/authz"
	echov1 "github.com/lynx-go/grpcapi/example/echo/v1"
	"github.com/lynx-go/grpcapi/policy"
	"github.com/lynx-go/grpcapi/policy/scope"
	"github.com/lynx-go/grpcapi/principal"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const serverTierMethod = "/torchwood.v1.Databases/Get"

// serverTierSet 构建 SERVER 档 + 实例门的策略集：kind 全部来自库与
// policy/scope，registry/vocabulary 按 MIGRATION §2.3 形态装配。
func serverTierSet(t *testing.T) *policy.Set {
	t.Helper()
	resourceKind, err := scope.ResourceKind(scope.ResourceOptions{
		ID:                scope.FieldID("databaseId", "database", "filter"),
		RequireVocabulary: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := policy.NewRegistry(
		policy.KindAuthenticated(),
		policy.KindClaim(),
		policy.KindPrincipal(),
		policy.ClaimKind("admin_role", "admin_roles", policy.MatchAny),
		scope.Kind(scope.Options{RequireVocabulary: true}),
		resourceKind,
	)
	if err != nil {
		t.Fatal(err)
	}
	set, err := policy.NewSetWithVocabulary(reg, policy.NewVocabulary(map[string][]string{
		"scope":    {"databases"},
		"resource": {"databases"},
	}), policy.Operation{
		ID:   serverTierMethod,
		Kind: policy.KindGRPC,
		Policy: policy.Policy{
			AnyOf: [][]policy.Requirement{
				{{Kind: "admin_role", Values: []string{"ops"}}},
				{
					{Kind: "scope", Values: []string{"databases:read"}},
					{Kind: "resource", Values: []string{"databases"}},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func TestServerTierCompositeGateExecutesInLibrary(t *testing.T) {
	set := serverTierSet(t)
	interceptor, err := authz.NewInterceptor(set, nil, authz.Options{})
	if err != nil {
		t.Fatal(err)
	}
	info := &grpc.UnaryServerInfo{FullMethod: serverTierMethod}
	handler := func(context.Context, any) (any, error) { return "ok", nil }

	call := func(p *principal.Principal, req any) error {
		ctx := context.Background()
		if p != nil {
			ctx = principal.With(ctx, p)
		}
		_, err := interceptor.Unary()(ctx, req, info, handler)
		return err
	}
	targeting := func(id string) *echov1.HearRequest { return &echov1.HearRequest{Filter: id} }

	cases := []struct {
		name string
		p    *principal.Principal
		req  any
		want error // nil = 放行
	}{
		{
			name: "admin 角色命中 any_of 第一组,实例门由资源整体授权放行",
			p:    &principal.Principal{Kind: "admin", Claims: map[string][]string{"admin_roles": {"ops"}}},
			req:  targeting("db1"),
		},
		{
			name: "API key scope 命中 any_of 第二组,资源整体授权放行任意实例",
			p:    &principal.Principal{Kind: "api_key", Claims: map[string][]string{"scopes": {"databases"}}},
			req:  targeting("db1"),
		},
		{
			name: "实例级 scope:寻址被授权实例放行",
			p:    &principal.Principal{Kind: "api_key", Claims: map[string][]string{"scopes": {"databases:read", "databases:db1"}}},
			req:  targeting("db1"),
		},
		{
			name: "实例级 scope:寻址其他实例被实例门拒绝",
			p:    &principal.Principal{Kind: "api_key", Claims: map[string][]string{"scopes": {"databases:read", "databases:db1"}}},
			req:  targeting("db2"),
			want: status.Error(codes.PermissionDenied, ""),
		},
		{
			name: "end_user 无 admin 角色无 scope:any_of 全组失败",
			p:    &principal.Principal{Kind: "user", Claims: map[string][]string{"roles": {"member"}}},
			req:  targeting("db1"),
			want: status.Error(codes.PermissionDenied, ""),
		},
		{
			name: "匿名:授权阶段即拒(Unauthenticated,不到 any_of)",
			p:    nil,
			req:  targeting("db1"),
			want: status.Error(codes.Unauthenticated, ""),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := call(tc.p, tc.req)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("want allow, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("want deny, got allow")
			}
			if got := status.Code(err); got != status.Code(tc.want) {
				t.Fatalf("code = %v, want %v (err=%v)", got, status.Code(tc.want), err)
			}
		})
	}
}

// 策略声明侧的闭环：同一棵树的 Format 输出稳定，可进 manifest/golden 对账
// （torchwood 路径 A 验收 §6 的比对基准）。
func TestServerTierPolicyFormatStable(t *testing.T) {
	set := serverTierSet(t)
	op, ok := set.Get(serverTierMethod)
	if !ok {
		t.Fatal("operation missing")
	}
	got := policy.Format(op.Policy)
	// 组内 requirement 按规范序输出（Format 会排序），跨层结构保持稳定。
	want := "any_of[admin_role(ops) | resource(databases) & scope(databases:read)]"
	if got != want {
		t.Fatalf("Format =\n  %s\nwant\n  %s", got, want)
	}
}

// TestServerTierOrCompositionWithOpAwareResource 是 torchwood 执行侧迁移
// 采用的组合形态（G-1 修复后的完备形态）：组间 OR + 方向感知实例门——
// 单个操作级 token（databases.read）过 scope 门、单个实例+方向 token
// （databases:db1.read）过 resource 门、无后缀实例 token（databases:db1）
// 过任一门，`*`/裸资源两者皆过。与 torchwood 旧逐 token 合取语义逐类
// 等价（见 torchwood docs/developer/21 §4 D-1/D-2）。
func TestServerTierOrCompositionWithOpAwareResource(t *testing.T) {
	resourceKind, err := scope.ResourceKind(scope.ResourceOptions{
		ID:                scope.FieldID("filter"),
		RequireVocabulary: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := policy.NewRegistry(
		policy.KindAuthenticated(),
		policy.KindClaim(),
		policy.KindPrincipal(),
		policy.ClaimKind("admin_role", "admin_roles", policy.MatchAny),
		scope.Kind(scope.Options{RequireVocabulary: true}),
		resourceKind,
	)
	if err != nil {
		t.Fatal(err)
	}
	readTree := policy.Policy{AnyOf: [][]policy.Requirement{
		{{Kind: "principal_kind", Values: []string{"admin"}}},
		{{Kind: "scope", Values: []string{"databases:read"}}},
		// 方向感知实例门：声明值携带方向，实例 token 的方向后缀须一致。
		{{Kind: "resource", Values: []string{"databases:read"}}},
	}}
	writeTree := readTree.Clone()
	writeTree.AnyOf[1][0].Values = []string{"databases:write"}
	writeTree.AnyOf[2][0].Values = []string{"databases:write"}
	set, err := policy.NewSetWithVocabulary(reg, policy.NewVocabulary(map[string][]string{
		"scope":    {"databases"},
		"resource": {"databases"},
	}),
		policy.Operation{ID: "/svc/Databases/Get", Kind: policy.KindGRPC, Policy: readTree},
		policy.Operation{ID: "/svc/Databases/Put", Kind: policy.KindGRPC, Policy: writeTree},
	)
	if err != nil {
		t.Fatal(err)
	}
	interceptor, err := authz.NewInterceptor(set, nil, authz.Options{})
	if err != nil {
		t.Fatal(err)
	}

	call := func(method, target string, scopes ...string) error {
		ctx := context.Background()
		if scopes != nil {
			ctx = principal.With(ctx, &principal.Principal{
				Kind:   "api_key",
				Claims: map[string][]string{"scopes": scopes},
			})
		}
		_, err := interceptor.Unary()(ctx, &echov1.HearRequest{Filter: target},
			&grpc.UnaryServerInfo{FullMethod: method}, func(context.Context, any) (any, error) { return nil, nil })
		return err
	}
	allow := func(err error) bool { return err == nil }

	// 操作级 token 单独持有即可调读/写面（torchwood 最常用形态行为不变）。
	if !allow(call("/svc/Databases/Get", "db1", "databases:read")) {
		t.Fatal("op-level token alone should pass read via scope gate")
	}
	if allow(call("/svc/Databases/Put", "db1", "databases:read")) {
		t.Fatal("op-level read token must not pass write")
	}
	// 实例+方向单 token（G-1 修复）：读 token 过读面的方向感知实例门。
	if !allow(call("/svc/Databases/Get", "db1", "databases:db1.read")) {
		t.Fatal("instance+op single token should pass matching direction")
	}
	if allow(call("/svc/Databases/Put", "db1", "databases:db1.read")) {
		t.Fatal("instance+read token must not pass write method")
	}
	if allow(call("/svc/Databases/Get", "db2", "databases:db1.read")) {
		t.Fatal("instance token must not address other instances")
	}
	// 无后缀实例 token = 全方向。
	if !allow(call("/svc/Databases/Put", "db1", "databases:db1")) {
		t.Fatal("suffix-less instance token grants all directions")
	}
	// 裸资源/通配符过两门。
	if !allow(call("/svc/Databases/Put", "any", "databases")) || !allow(call("/svc/Databases/Get", "any", "*")) {
		t.Fatal("resource-wide / wildcard should pass both gates")
	}
	// 匿名仍 Unauthenticated。
	if code := status.Code(call("/svc/Databases/Get", "db1")); code != codes.Unauthenticated {
		t.Fatalf("anonymous code = %v, want Unauthenticated", code)
	}
}
