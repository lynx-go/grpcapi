package apikey_test

import (
	"context"
	"testing"
	"time"

	"github.com/lynx-go/grpcapi/authn"
	"github.com/lynx-go/grpcapi/authn/apikey"
	"github.com/lynx-go/grpcapi/principal"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type memStore map[string]*apikey.Key

func (m memStore) Lookup(_ context.Context, hash string) (*apikey.Key, error) {
	k, ok := m[hash]
	if !ok {
		return nil, apikey.ErrNotFound
	}
	return k, nil
}

func TestAuthenticate(t *testing.T) {
	raw := "sk_test_123"
	store := memStore{
		apikey.Hash(raw): {
			ID:          "key1",
			PrincipalID: "svc1",
			Scopes:      []string{"notes:write"},
			Claims:      map[string][]string{"tenant": {"acme"}},
		},
	}
	a, err := apikey.New(apikey.Config{Store: store, Now: func() time.Time { return time.Unix(1000, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	p, err := a.Authenticate(context.Background(), authn.Credentials{APIKeys: []string{raw}})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if p.ID != "svc1" || p.Kind != principal.KindAPIKey {
		t.Fatalf("principal = %+v", p)
	}
	if got := p.Claim("scopes"); len(got) != 1 || got[0] != "notes:write" {
		t.Fatalf("scopes = %v", got)
	}
	if got := p.Claim("tenant"); len(got) != 1 || got[0] != "acme" {
		t.Fatalf("tenant = %v", got)
	}
	if p.Attribute("api_key_id") != "key1" {
		t.Fatalf("api_key_id = %q", p.Attribute("api_key_id"))
	}
}

func TestAuthenticateRejects(t *testing.T) {
	raw := "sk_test_123"
	now := time.Unix(1000, 0)
	store := memStore{
		apikey.Hash(raw): {ID: "key1", PrincipalID: "svc1", ExpiresAt: now.Add(-time.Minute)},
	}
	a, _ := apikey.New(apikey.Config{Store: store, Now: func() time.Time { return now }})

	if _, err := a.Authenticate(context.Background(), authn.Credentials{APIKeys: []string{raw}}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expired code = %v", status.Code(err))
	}
	if _, err := a.Authenticate(context.Background(), authn.Credentials{APIKeys: []string{"unknown"}}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unknown code = %v", status.Code(err))
	}
	if p, err := a.Authenticate(context.Background(), authn.Credentials{}); err != nil || p != nil {
		t.Fatalf("no credentials = %+v, %v", p, err)
	}
}

func TestPrefixMismatchIsNotRecognized(t *testing.T) {
	a, _ := apikey.New(apikey.Config{Store: memStore{}, Prefix: "sk_"})
	p, err := a.Authenticate(context.Background(), authn.Credentials{APIKeys: []string{"other_123"}})
	if err != nil || p != nil {
		t.Fatalf("prefix mismatch should be ignored: %+v, %v", p, err)
	}
}

type errStore struct{}

func (errStore) Lookup(context.Context, string) (*apikey.Key, error) {
	return nil, context.DeadlineExceeded
}

func TestStoreFailureIsUnavailable(t *testing.T) {
	a, _ := apikey.New(apikey.Config{Store: errStore{}})
	_, err := a.Authenticate(context.Background(), authn.Credentials{APIKeys: []string{"sk_123"}})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", status.Code(err))
	}
}
