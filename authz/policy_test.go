package authz

import (
	"reflect"
	"strings"
	"testing"
)

func TestNewPolicySetDuplicateMethod(t *testing.T) {
	_, err := NewPolicySet(
		MethodPolicy{Method: "/pkg.Svc/Get"},
		MethodPolicy{Method: "/pkg.Svc/Get"},
	)
	if err == nil || !strings.Contains(err.Error(), "duplicate method policy /pkg.Svc/Get") {
		t.Fatalf("NewPolicySet duplicate = %v, want duplicate method policy error", err)
	}
}

func TestPolicySetGet(t *testing.T) {
	p := MethodPolicy{Method: "/pkg.Svc/Get", Access: AccessPublic}
	set, err := NewPolicySet(p)
	if err != nil {
		t.Fatalf("NewPolicySet: %v", err)
	}
	got, ok := set.Get("/pkg.Svc/Get")
	if !ok || !reflect.DeepEqual(got, p) {
		t.Fatalf("Get = (%+v, %v), want (%+v, true)", got, ok, p)
	}
	if _, ok := set.Get("/pkg.Svc/Missing"); ok {
		t.Fatal("Get missing method = ok, want false")
	}
	var nilSet *PolicySet
	if _, ok := nilSet.Get("/pkg.Svc/Get"); ok {
		t.Fatal("nil set Get = ok, want false")
	}
}

func TestPolicySetMethodsSortedStable(t *testing.T) {
	// 输入乱序，输出必须按 Method 字典序（golden 列表）。
	in := []MethodPolicy{
		{Method: "/pkg.Svc/Update"},
		{Method: "/pkg.Svc/Add"},
		{Method: "/pkg.Aaa/Get"},
		{Method: "/pkg.Svc/Delete"},
	}
	set, err := NewPolicySet(in...)
	if err != nil {
		t.Fatalf("NewPolicySet: %v", err)
	}
	var got []string
	for _, p := range set.Methods() {
		got = append(got, p.Method)
	}
	want := []string{"/pkg.Aaa/Get", "/pkg.Svc/Add", "/pkg.Svc/Delete", "/pkg.Svc/Update"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Methods() = %v, want %v", got, want)
	}
}

func TestPolicySetScopeRule(t *testing.T) {
	scope := &ScopeRule{Resource: "databases", Op: ScopeRead}
	set, err := NewPolicySet(
		MethodPolicy{Method: "/pkg.Svc/Get", Access: AccessServer, Scope: scope},
		MethodPolicy{Method: "/pkg.Svc/Purge", Access: AccessPermission},
		MethodPolicy{Method: "/pkg.Svc/Ping", Access: AccessPublic},
		MethodPolicy{Method: "/pkg.Svc/ServerNoScope", Access: AccessServer},
	)
	if err != nil {
		t.Fatalf("NewPolicySet: %v", err)
	}
	rule := set.ScopeRule("/pkg.Svc/Get")
	if rule == nil || *rule != *scope {
		t.Fatalf("ScopeRule = %+v, want %+v", rule, scope)
	}
	// 非 SERVER 面与未登记方法：nil（fail-closed）。
	if r := set.ScopeRule("/pkg.Svc/Purge"); r != nil {
		t.Fatalf("PERMISSION method ScopeRule = %+v, want nil", r)
	}
	if r := set.ScopeRule("/pkg.Svc/Ping"); r != nil {
		t.Fatalf("PUBLIC method ScopeRule = %+v, want nil", r)
	}
	if r := set.ScopeRule("/pkg.Svc/ServerNoScope"); r != nil {
		t.Fatalf("SERVER without scope ScopeRule = %+v, want nil", r)
	}
	if r := set.ScopeRule("/pkg.Svc/Missing"); r != nil {
		t.Fatalf("missing method ScopeRule = %+v, want nil", r)
	}
	// 返回副本：改写不得影响内部状态。
	rule.Resource = "hacked"
	if again := set.ScopeRule("/pkg.Svc/Get"); again.Resource != "databases" {
		t.Fatalf("ScopeRule returned shared state: %+v", again)
	}
}

func TestPolicySetAllowedAdminRoles(t *testing.T) {
	set, err := NewPolicySet(
		MethodPolicy{Method: "/pkg.Svc/Get", Access: AccessServer, AdminRoles: []string{"admin", "owner"}},
		MethodPolicy{Method: "/pkg.Svc/List", Access: AccessServer}, // 不限角色
		MethodPolicy{Method: "/pkg.Svc/Purge", Access: AccessPermission, AdminRoles: []string{"owner"}},
	)
	if err != nil {
		t.Fatalf("NewPolicySet: %v", err)
	}
	if got := set.AllowedAdminRoles("/pkg.Svc/Get"); !reflect.DeepEqual(got, []string{"admin", "owner"}) {
		t.Fatalf("AllowedAdminRoles = %v, want [admin owner]", got)
	}
	if got := set.AllowedAdminRoles("/pkg.Svc/List"); got != nil {
		t.Fatalf("unrestricted SERVER roles = %v, want nil", got)
	}
	if got := set.AllowedAdminRoles("/pkg.Svc/Purge"); got != nil {
		t.Fatalf("non-SERVER roles = %v, want nil", got)
	}
	if got := set.AllowedAdminRoles("/pkg.Svc/Missing"); got != nil {
		t.Fatalf("missing method roles = %v, want nil", got)
	}
}

func TestPolicySetVocabulary(t *testing.T) {
	set, err := NewPolicySet(
		MethodPolicy{Method: "/pkg.Svc/A", Access: AccessServer, Scope: &ScopeRule{Resource: "storage", Op: ScopeWrite}},
		MethodPolicy{Method: "/pkg.Svc/B", Access: AccessServer, Scope: &ScopeRule{Resource: "databases", Op: ScopeRead}},
		MethodPolicy{Method: "/pkg.Svc/C", Access: AccessServer, Scope: &ScopeRule{Resource: "storage", Op: ScopeAdmin}},
		MethodPolicy{Method: "/pkg.Svc/D", Access: AccessPublic}, // 无 scope，不参与
	)
	if err != nil {
		t.Fatalf("NewPolicySet: %v", err)
	}
	got := set.Vocabulary()
	want := []string{"databases", "storage"} // 去重 + 字典序
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Vocabulary() = %v, want %v", got, want)
	}
	empty, err := NewPolicySet()
	if err != nil {
		t.Fatalf("NewPolicySet: %v", err)
	}
	if got := empty.Vocabulary(); len(got) != 0 {
		t.Fatalf("empty set Vocabulary() = %v, want empty", got)
	}
}
