package scope_test

import (
	"context"
	"strings"
	"testing"

	"github.com/lynx-go/grpcapi/policy"
	"github.com/lynx-go/grpcapi/policy/scope"
	"github.com/lynx-go/grpcapi/principal"
)

func TestParse(t *testing.T) {
	good, err := scope.Parse([]string{"*", "all", "notes", "notes:read", "notes:write", "notes:admin"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(good) != 6 {
		t.Fatalf("Parse len = %d", len(good))
	}
	for _, bad := range []string{"", "notes:read:extra", "notes:*", "notes:bad", "*.read"} {
		t.Run(bad, func(t *testing.T) {
			if _, err := scope.Parse([]string{bad}); err == nil {
				t.Fatalf("Parse(%q) should fail", bad)
			}
		})
	}
}

func TestSetSatisfies(t *testing.T) {
	set := scope.Set{"notes", "databases:read"}
	cases := []struct {
		resource, op string
		want         bool
	}{
		{"notes", "", true},
		{"notes", "write", true},
		{"databases", "read", true},
		{"databases", "write", false},
		{"other", "", false},
	}
	for _, tc := range cases {
		if got := set.Satisfies(tc.resource, tc.op); got != tc.want {
			t.Errorf("Satisfies(%q,%q) = %v, want %v", tc.resource, tc.op, got, tc.want)
		}
	}
	if !(scope.Set{"*"}).Satisfies("anything", "admin") {
		t.Error("wildcard should satisfy")
	}
}

func TestKindValidate(t *testing.T) {
	kind := scope.Kind(scope.Options{RequireVocabulary: true})
	vocab := policy.NewVocabulary(map[string][]string{"scope": {"notes", "databases"}})

	if err := kind.Validate(policy.Requirement{Kind: "scope", Values: []string{"notes:write"}}, vocab); err != nil {
		t.Fatalf("valid scope: %v", err)
	}
	if err := kind.Validate(policy.Requirement{Kind: "scope", Values: []string{"other:write"}}, vocab); err == nil ||
		!strings.Contains(err.Error(), "not in vocabulary") {
		t.Fatalf("outside vocabulary: %v", err)
	}
	if err := kind.Validate(policy.Requirement{Kind: "scope", Values: []string{"notes:bad"}}, vocab); err == nil {
		t.Fatal("unknown op should fail")
	}
	if err := kind.Validate(policy.Requirement{Kind: "scope", Values: []string{"*"}}, vocab); err != nil {
		t.Fatalf("wildcard should be allowed: %v", err)
	}

	strict := scope.Kind(scope.Options{DisallowWildcard: true})
	if err := strict.Validate(policy.Requirement{Kind: "scope", Values: []string{"*"}}, vocab); err == nil {
		t.Fatal("strict wildcard should fail")
	}

	noVocab := scope.Kind(scope.Options{RequireVocabulary: true})
	if err := noVocab.Validate(policy.Requirement{Kind: "scope", Values: []string{"notes"}}, nil); err == nil {
		t.Fatal("missing vocabulary should fail")
	}
}

func TestKindEvaluate(t *testing.T) {
	kind := scope.Kind(scope.Options{})
	p := &principal.Principal{Claims: map[string][]string{"scopes": {"notes:read"}}}
	ec := policy.EvalContext{Principal: p}

	cases := []struct {
		name string
		req  policy.Requirement
		want bool
	}{
		{"exact op", policy.Requirement{Kind: "scope", Values: []string{"notes:read"}}, true},
		{"wrong op", policy.Requirement{Kind: "scope", Values: []string{"notes:write"}}, false},
		{"resource only", policy.Requirement{Kind: "scope", Values: []string{"notes"}}, true},
		{"any of", policy.Requirement{Kind: "scope", Values: []string{"other:read", "notes:read"}}, true},
		{"all", policy.Requirement{Kind: "scope", Match: policy.MatchAll, Values: []string{"notes:read"}}, true},
		{"all missing", policy.Requirement{Kind: "scope", Match: policy.MatchAll, Values: []string{"notes:read", "notes:write"}}, false},
		{"wildcard", policy.Requirement{Kind: "scope", Values: []string{"*"}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := kind.Evaluate(context.Background(), ec, tc.req)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if got != tc.want {
				t.Fatalf("Evaluate = %v, want %v", got, tc.want)
			}
		})
	}

	if got, _ := kind.Evaluate(context.Background(), policy.EvalContext{}, policy.Requirement{Kind: "scope", Values: []string{"notes"}}); got {
		t.Fatal("nil principal should not satisfy")
	}

	strict := scope.Kind(scope.Options{DisallowWildcard: true})
	if got, _ := strict.Evaluate(context.Background(), policy.EvalContext{
		Principal: &principal.Principal{Claims: map[string][]string{"scopes": {"*"}}},
	}, policy.Requirement{Kind: "scope", Values: []string{"notes"}}); got {
		t.Fatal("strict mode should ignore wildcard principal scopes")
	}
}
