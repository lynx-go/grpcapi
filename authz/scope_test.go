package authz

import (
	"strings"
	"testing"
)

func TestParseScopeSetValidForms(t *testing.T) {
	// 四形态全覆盖：*、all、resource、resource.op（含含 '.' 资源名的末段方向）。
	for _, raw := range [][]string{
		{"*"},
		{"all"},
		{"databases"},
		{"databases.read"},
		{"storage.write"},
		{"leaderboards.admin"},
		{"*", "all", "databases", "databases.read", "storage.write", "leaderboards.admin", "a.b.read"},
		{}, // 空集合合法（无 scope 的 key）。
	} {
		ss, err := ParseScopeSet(raw)
		if err != nil {
			t.Fatalf("ParseScopeSet(%v) = error %v, want nil", raw, err)
		}
		if len(ss) != len(raw) {
			t.Fatalf("ParseScopeSet(%v) kept %d tokens, want %d", raw, len(ss), len(raw))
		}
	}
}

func TestParseScopeSetInvalidTokens(t *testing.T) {
	for _, tc := range []struct {
		raw     string
		wantErr string // 期望错误信息包含的子串
	}{
		{"", "empty scope"},
		{"databases.create", `unknown op "create"`},
		{"databases.", `unknown op ""`},
		{".read", "missing resource before op"},
		{"databases:blog", "instance-scoped"},
		{"databases:blog.read", "instance-scoped"},
		{"databases.*", "wildcard"},
		{"*.read", "wildcard"},
		{"all.read", "reserved word"},
		{"*.sub.read", "wildcard"},
	} {
		ss, err := ParseScopeSet([]string{"databases", tc.raw})
		if err == nil {
			t.Fatalf("ParseScopeSet with %q = %v, want error", tc.raw, ss)
		}
		if !strings.Contains(err.Error(), tc.raw) {
			t.Fatalf("error %q must name the offending token %q", err, tc.raw)
		}
		if !strings.Contains(err.Error(), tc.wantErr) {
			t.Fatalf("error %q must contain %q", err, tc.wantErr)
		}
		// 一个坏 token 不应拖出部分结果。
		if ss != nil {
			t.Fatalf("ParseScopeSet with %q returned non-nil set %v", tc.raw, ss)
		}
	}
}

func TestParseScopeSetAggregatesAllViolations(t *testing.T) {
	_, err := ParseScopeSet([]string{"", "databases:blog", "x.wrong"})
	if err == nil {
		t.Fatal("want error")
	}
	for _, want := range []string{`scope ""`, `scope "databases:blog"`, `scope "x.wrong"`} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q must contain %q", err, want)
		}
	}
}

func TestScopeSetSatisfies(t *testing.T) {
	dbRead := ScopeRule{Resource: "databases", Op: ScopeRead}
	dbWrite := ScopeRule{Resource: "databases", Op: ScopeWrite}
	dbAdmin := ScopeRule{Resource: "databases", Op: ScopeAdmin}
	stRead := ScopeRule{Resource: "storage", Op: ScopeRead}

	must := func(raw []string) ScopeSet {
		t.Helper()
		ss, err := ParseScopeSet(raw)
		if err != nil {
			t.Fatalf("ParseScopeSet(%v): %v", raw, err)
		}
		return ss
	}

	cases := []struct {
		raw  []string
		rule ScopeRule
		want bool
	}{
		// * 与 all 恒真。
		{[]string{"*"}, dbRead, true},
		{[]string{"*"}, dbWrite, true},
		{[]string{"*"}, stRead, true},
		{[]string{"all"}, dbRead, true},
		{[]string{"all"}, stRead, true},
		// resource 形态：精确匹配资源，任意方向放行。
		{[]string{"databases"}, dbRead, true},
		{[]string{"databases"}, dbWrite, true},
		{[]string{"databases"}, dbAdmin, true},
		{[]string{"databases"}, stRead, false},
		// resource.op 形态：资源与方向都需精确匹配。
		{[]string{"databases.read"}, dbRead, true},
		{[]string{"databases.read"}, dbWrite, false},
		{[]string{"databases.read"}, dbAdmin, false},
		{[]string{"databases.write"}, dbRead, false},
		// 多 token：任一命中即真。
		{[]string{"storage.write", "databases.read"}, dbRead, true},
		{[]string{"storage.write", "databases.read"}, dbAdmin, false},
		// 空集合恒假。
		{[]string{}, dbRead, false},
	}
	for _, tc := range cases {
		if got := must(tc.raw).Satisfies(tc.rule); got != tc.want {
			t.Errorf("ScopeSet(%v).Satisfies(%+v) = %v, want %v", tc.raw, tc.rule, got, tc.want)
		}
	}
}

func TestScopeSetSatisfiesFailsClosedOnInvalidTokens(t *testing.T) {
	// 手工构造（未经 ParseScopeSet 校验）的非法 token 一律不匹配。
	dbRead := ScopeRule{Resource: "databases", Op: ScopeRead}
	for _, raw := range []ScopeSet{
		{"databases.owner"}, // 未知方向
		{"databases."},      // 空方向
		{"databases:blog"},  // 实例限定不进库
		{""},                // 空串
	} {
		if raw.Satisfies(dbRead) {
			t.Errorf("ScopeSet(%v).Satisfies(%+v) = true, want false (fail-closed)", raw, dbRead)
		}
	}
}
