package admin_test

import (
	"context"
	"testing"

	"github.com/lynx-go/grpcapi/authn/admin"
	"github.com/lynx-go/grpcapi/principal"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type memStore struct {
	info *admin.Admin
	err  error
}

func (m memStore) Get(context.Context, string) (*admin.Admin, error) {
	return m.info, m.err
}

func TestEnrichSuspensionRevokesRoles(t *testing.T) {
	e, err := admin.New(admin.Config{Store: memStore{info: &admin.Admin{
		Roles:     []string{"superadmin", "operator"},
		Suspended: true,
		Attrs:     map[string]string{"admin_email": "a@example.com"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	p := &principal.Principal{
		ID:     "u1",
		Claims: map[string][]string{"admin_roles": {"operator"}},
	}
	if err := e.Enrich(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if got := p.Claim("admin_roles"); len(got) != 0 {
		t.Fatalf("suspended admin_roles = %v, want revoked", got)
	}
	if got := p.Claim("admin_suspended"); len(got) != 1 || got[0] != "true" {
		t.Fatalf("admin_suspended = %v", got)
	}
	if p.Attribute("admin_email") != "a@example.com" {
		t.Fatalf("admin_email = %q", p.Attribute("admin_email"))
	}
}

func TestEnrichActiveRolesReplaceTokenClaims(t *testing.T) {
	// store 有记录时 store 权威：整体替换，token 自带的 admin_roles
	// 不参与合并——否则「JWT 带了 admin role 就自动成为后台管理员」。
	e, _ := admin.New(admin.Config{Store: memStore{info: &admin.Admin{
		Roles: []string{"superadmin"},
	}}})
	p := &principal.Principal{
		ID:     "u1",
		Claims: map[string][]string{"admin_roles": {"operator"}},
	}
	if err := e.Enrich(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if got := p.Claim("admin_roles"); len(got) != 1 || got[0] != "superadmin" {
		t.Fatalf("admin_roles = %v, want store-only [superadmin]", got)
	}
	if got := p.Claim("admin_suspended"); len(got) != 0 {
		t.Fatalf("admin_suspended = %v, want empty", got)
	}
}

func TestEnrichEmptyStoreRolesRevokesTokenClaims(t *testing.T) {
	// 记录存在但无角色 = 明确撤权：凭证自带的 admin_roles 一并撤销。
	e, _ := admin.New(admin.Config{Store: memStore{info: &admin.Admin{}}})
	p := &principal.Principal{
		ID:     "u1",
		Claims: map[string][]string{"admin_roles": {"operator"}},
	}
	if err := e.Enrich(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if got := p.Claim("admin_roles"); len(got) != 0 {
		t.Fatalf("admin_roles = %v, want revoked", got)
	}
}

func TestEnrichNotFoundKeepsTokenClaims(t *testing.T) {
	// 无 store 记录：凭证自带 claim 放行（供无 store 部署走 IdP 签发）。
	e, _ := admin.New(admin.Config{Store: memStore{err: admin.ErrNotFound}})
	p := &principal.Principal{
		ID:     "u1",
		Claims: map[string][]string{"admin_roles": {"operator"}},
	}
	if err := e.Enrich(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if got := p.Claim("admin_roles"); len(got) != 1 || got[0] != "operator" {
		t.Fatalf("admin_roles = %v, want token-borne [operator]", got)
	}
}

func TestEnrichNotFoundIsNoop(t *testing.T) {
	e, _ := admin.New(admin.Config{Store: memStore{err: admin.ErrNotFound}})
	p := &principal.Principal{ID: "u1"}
	if err := e.Enrich(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if len(p.Claims) != 0 {
		t.Fatalf("claims = %+v", p.Claims)
	}
}

func TestEnrichStoreFailureIsUnavailable(t *testing.T) {
	e, _ := admin.New(admin.Config{Store: memStore{err: context.DeadlineExceeded}})
	err := e.Enrich(context.Background(), &principal.Principal{ID: "u1"})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", status.Code(err))
	}
}
