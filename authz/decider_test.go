package authz_test

import (
	"context"
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
