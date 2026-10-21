package authz_test

import (
	"context"
	"strings"
	"testing"

	"github.com/lynx-go/grpcapi/authz"
	"github.com/lynx-go/grpcapi/policy"
	"github.com/lynx-go/grpcapi/principal"
	"google.golang.org/grpc/codes"
)

func testSet(t *testing.T, ops ...policy.Operation) *policy.Set {
	t.Helper()
	set, err := policy.NewSet(ops...)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	return set
}

func op(id string, p policy.Policy) policy.Operation {
	return policy.Operation{ID: id, Kind: policy.KindGRPC, Exposure: policy.ExposureInternal, Policy: p}
}

func TestRequirementDecider(t *testing.T) {
	set := testSet(t,
		op("/svc/Public", policy.Policy{Anonymous: true}),
		op("/svc/Auth", policy.Policy{Require: []policy.Requirement{{Kind: "authenticated"}}}),
		op("/svc/Role", policy.Policy{Require: []policy.Requirement{{Kind: "role", Values: []string{"admin"}}}}),
		op("/svc/AnyOf", policy.Policy{AnyOf: [][]policy.Requirement{
			{{Kind: "role", Values: []string{"admin"}}},
			{{Kind: "scope", Values: []string{"notes:write"}}},
		}}),
		op("/svc/Forbid", policy.Policy{
			Require: []policy.Requirement{{Kind: "authenticated"}},
			Forbid:  []policy.Requirement{{Kind: "claim", Params: map[string]string{"name": "status"}, Values: []string{"suspended"}}},
		}),
	)
	d, err := authz.NewRequirementDecider(set)
	if err != nil {
		t.Fatalf("NewRequirementDecider: %v", err)
	}

	user := &principal.Principal{ID: "u1", Kind: principal.KindUser}
	admin := &principal.Principal{ID: "a1", Kind: principal.KindUser, Claims: map[string][]string{"roles": {"admin"}}}
	scoped := &principal.Principal{ID: "k1", Kind: principal.KindAPIKey, Claims: map[string][]string{"scopes": {"notes:write"}}}
	suspended := &principal.Principal{ID: "s1", Kind: principal.KindUser, Claims: map[string][]string{"status": {"suspended"}}}

	cases := []struct {
		name string
		id   string
		p    *principal.Principal
		want bool
		code codes.Code
	}{
		{"public anonymous", "/svc/Public", nil, true, codes.OK},
		{"auth missing principal", "/svc/Auth", nil, false, codes.Unauthenticated},
		{"auth user", "/svc/Auth", user, true, codes.OK},
		{"role denied", "/svc/Role", user, false, codes.PermissionDenied},
		{"role allowed", "/svc/Role", admin, true, codes.OK},
		{"any_of role", "/svc/AnyOf", admin, true, codes.OK},
		{"any_of scope", "/svc/AnyOf", scoped, true, codes.OK},
		{"any_of none", "/svc/AnyOf", user, false, codes.PermissionDenied},
		{"forbid", "/svc/Forbid", suspended, false, codes.PermissionDenied},
		{"forbid passes", "/svc/Forbid", user, true, codes.OK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			operation, _ := set.Get(tc.id)
			got, err := d.Decide(context.Background(), authz.Request{
				EvalContext: policy.EvalContext{Operation: operation, Principal: tc.p},
			})
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}
			if got.Allow != tc.want {
				t.Fatalf("Allow = %v, want %v (decision %+v)", got.Allow, tc.want, got)
			}
			if !tc.want && got.Code != tc.code {
				t.Fatalf("Code = %v, want %v", got.Code, tc.code)
			}
		})
	}
}

func TestRequirementDeciderRejectsNonEvaluableKind(t *testing.T) {
	reg, err := policy.NewRegistry(policy.RequirementKind{Name: "noeval"})
	if err != nil {
		t.Fatal(err)
	}
	set, err := policy.NewSetWithRegistry(reg, policy.Operation{
		ID: "/svc/X", Kind: policy.KindGRPC, Exposure: policy.ExposureInternal,
		Policy: policy.Policy{Require: []policy.Requirement{{Kind: "noeval"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authz.NewRequirementDecider(set); err == nil {
		t.Fatal("kind without Evaluate should fail at construction")
	}
}

func TestRequirementDeciderFailClosedOnMalformedPolicy(t *testing.T) {
	// 求值端防线：即使绕过 Build/NewSet 校验构造出畸形策略，判定也必须
	// fail-closed（Internal 拒绝），不能静默放行。
	set := testSet(t, op("/svc/Public", policy.Policy{Anonymous: true}))
	d, err := authz.NewRequirementDecider(set)
	if err != nil {
		t.Fatalf("NewRequirementDecider: %v", err)
	}
	cases := []struct {
		name   string
		p      policy.Policy
		reason string
	}{
		{"unexpanded preset", policy.Policy{Preset: "tw.server"}, "empty or unexpanded policy"},
		{"empty policy", policy.Policy{}, "empty or unexpanded policy"},
		{"anonymous with requirements", policy.Policy{
			Anonymous: true,
			Require:   []policy.Requirement{{Kind: "authenticated"}},
		}, "anonymous policy with requirements"},
		{"empty any_of group", policy.Policy{
			AnyOf: [][]policy.Requirement{{}},
		}, "empty any_of group"},
		{"invalid match", policy.Policy{
			Require: []policy.Requirement{{Kind: "authenticated", Match: policy.Match(42)}},
		}, "invalid requirement match"},
	}
	for _, tc := range cases {
		dec, err := d.Decide(context.Background(), authz.Request{
			EvalContext: policy.EvalContext{Operation: op("/svc/Malformed", tc.p)},
			Stream:      false,
		})
		if err != nil {
			t.Errorf("%s: unexpected error: %v", tc.name, err)
			continue
		}
		if dec.Allow {
			t.Errorf("%s: malformed policy must not allow", tc.name)
		}
		if dec.Code != codes.Internal {
			t.Errorf("%s: code = %v, want Internal (fail-closed)", tc.name, dec.Code)
		}
		if !strings.Contains(dec.Reason, tc.reason) {
			t.Errorf("%s: reason = %q, want containing %q", tc.name, dec.Reason, tc.reason)
		}
	}
}

func TestRequirementDeciderAnyOfMergedAlternatives(t *testing.T) {
	// 语义钉死（README「策略速查」）：inherit_default 合并时 any_of 各组
	// 并列为备选，组间恒为 OR，不做跨层笛卡尔 AND——service 默认
	// any_of[[admin]] + 方法 any_of[[viewer]] 的有效策略等价于
	// any_of[[admin], [viewer]]，viewer 单角色即放行。需要交集时把两组
	// 条件写进同一个 any_of 组（组内 AND）。
	set := testSet(t, op("/svc/Merged", policy.Policy{
		AnyOf: [][]policy.Requirement{
			{{Kind: "role", Values: []string{"admin"}}},
			{{Kind: "role", Values: []string{"viewer"}}},
		},
	}))
	d, err := authz.NewRequirementDecider(set)
	if err != nil {
		t.Fatalf("NewRequirementDecider: %v", err)
	}
	opr := set.Operations()[0]
	viewer := &principal.Principal{ID: "v1", Kind: principal.KindUser, Claims: map[string][]string{"roles": {"viewer"}}}
	admin := &principal.Principal{ID: "a1", Kind: principal.KindUser, Claims: map[string][]string{"roles": {"admin"}}}
	nobody := &principal.Principal{ID: "u1", Kind: principal.KindUser}
	for _, tc := range []struct {
		name string
		p    *principal.Principal
		want bool
	}{
		{"viewer alone passes", viewer, true},
		{"admin alone passes", admin, true},
		{"plain user denied", nobody, false},
	} {
		dec, err := d.Decide(context.Background(), authz.Request{
			EvalContext: policy.EvalContext{Operation: opr, Principal: tc.p},
		})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if dec.Allow != tc.want {
			t.Errorf("%s: allow = %v, want %v", tc.name, dec.Allow, tc.want)
		}
	}
}
