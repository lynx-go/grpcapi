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

func TestEnrichMergesActiveRoles(t *testing.T) {
	e, _ := admin.New(admin.Config{Store: memStore{info: &admin.Admin{
		Roles: []string{"superadmin", "operator"},
	}}})
	p := &principal.Principal{
		ID:     "u1",
		Claims: map[string][]string{"admin_roles": {"operator"}},
	}
	if err := e.Enrich(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if got := p.Claim("admin_roles"); len(got) != 2 || got[0] != "operator" || got[1] != "superadmin" {
		t.Fatalf("admin_roles = %v, want union of 2", got)
	}
	if got := p.Claim("admin_suspended"); len(got) != 0 {
		t.Fatalf("admin_suspended = %v, want empty", got)
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
