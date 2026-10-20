package principal_test

import (
	"context"
	"testing"

	"github.com/lynx-go/grpcapi/principal"
)

func TestContextRoundTrip(t *testing.T) {
	ctx := context.Background()
	if _, ok := principal.From(ctx); ok {
		t.Fatal("empty ctx should not carry Principal")
	}
	want := &principal.Principal{ID: "u1", Kind: principal.KindUser}
	ctx = principal.With(ctx, want)
	got, ok := principal.From(ctx)
	if !ok || got != want {
		t.Fatalf("From = %v, %v; want %v", got, ok, want)
	}
	if principal.MustFrom(ctx) != want {
		t.Fatal("MustFrom returned a different principal")
	}
}

func TestWithNilIsNoop(t *testing.T) {
	ctx := context.Background()
	if got := principal.With(ctx, nil); got != ctx {
		t.Fatal("With(nil) should return the original ctx")
	}
}

func TestClaims(t *testing.T) {
	p := &principal.Principal{
		ID:   "u1",
		Kind: principal.KindUser,
		Claims: map[string][]string{
			"roles":       {"admin", "operator"},
			"permissions": {"notes.read", "notes.write"},
			"tenant":      {"acme"},
		},
	}

	if !p.HasClaim("roles", "admin") {
		t.Error("HasClaim roles/admin = false")
	}
	if p.HasClaim("roles", "viewer") {
		t.Error("HasClaim roles/viewer = true")
	}
	if !p.HasAllClaims("permissions", "notes.read", "notes.write") {
		t.Error("HasAllClaims should match all")
	}
	if p.HasAllClaims("permissions", "notes.read", "notes.delete") {
		t.Error("HasAllClaims matched a missing value")
	}
	if !p.HasClaim("tenant") {
		t.Error("HasClaim with no values should check presence")
	}
	if p.HasClaim("missing") {
		t.Error("HasClaim on missing claim = true")
	}
	if !p.HasKind(principal.KindUser) || p.HasKind(principal.KindService) {
		t.Error("HasKind mismatch")
	}
}

func TestClaimReturnsCopy(t *testing.T) {
	p := &principal.Principal{Claims: map[string][]string{"roles": {"admin"}}}
	got := p.Claim("roles")
	got[0] = "mutated"
	if p.Claims["roles"][0] != "admin" {
		t.Fatal("Claim exposed internal slice")
	}
}

func TestCloneIsDeep(t *testing.T) {
	p := &principal.Principal{
		ID:     "u1",
		Kind:   principal.KindUser,
		Claims: map[string][]string{"roles": {"admin"}},
		Attrs:  map[string]string{"email": "a@example.com"},
	}
	c := p.Clone()
	c.Claims["roles"][0] = "mutated"
	c.Attrs["email"] = "b@example.com"
	if p.Claims["roles"][0] != "admin" || p.Attrs["email"] != "a@example.com" {
		t.Fatal("Clone is not deep")
	}

	var nilPrincipal *principal.Principal
	if nilPrincipal.Clone() != nil {
		t.Fatal("nil Clone should return nil")
	}
	if nilPrincipal.Claim("x") != nil || nilPrincipal.Attribute("x") != "" {
		t.Fatal("nil receiver getters should be zero")
	}
	if nilPrincipal.HasClaim("x") || nilPrincipal.HasKind("user") {
		t.Fatal("nil receiver predicates should be false")
	}
}
