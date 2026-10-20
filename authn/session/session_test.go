package session_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lynx-go/grpcapi/authn"
	"github.com/lynx-go/grpcapi/authn/session"
	"github.com/lynx-go/grpcapi/principal"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type memStore map[string]*session.Session

func (m memStore) Get(_ context.Context, id string) (*session.Session, error) {
	s, ok := m[id]
	if !ok {
		return nil, session.ErrNotFound
	}
	return s, nil
}
func (m memStore) Create(_ context.Context, s *session.Session) error { m[s.ID] = s; return nil }
func (m memStore) Touch(context.Context, string, time.Duration) error { return nil }
func (m memStore) Delete(_ context.Context, id string) error          { delete(m, id); return nil }

func TestIssueAndAuthenticate(t *testing.T) {
	store := memStore{}
	now := time.Unix(1000, 0)
	a, err := session.New(session.Config{
		Store: store, SigningKey: []byte("secret"), TTL: time.Hour,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if !a.RequiresCSRF() {
		t.Fatal("session must require CSRF")
	}
	p := &principal.Principal{ID: "u1", Kind: principal.KindUser, Claims: map[string][]string{"roles": {"admin"}}}
	rec := httptest.NewRecorder()
	if err := a.Issue(context.Background(), rec, p); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %+v", cookies)
	}
	creds := authn.Credentials{Cookies: []string{"session=" + cookies[0].Value}}
	got, err := a.Authenticate(context.Background(), creds)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got.ID != "u1" || len(got.Claim("roles")) != 1 || got.Claim("roles")[0] != "admin" {
		t.Fatalf("principal = %+v", got)
	}
}

func TestTamperedAndExpired(t *testing.T) {
	store := memStore{}
	now := time.Unix(1000, 0)
	a, _ := session.New(session.Config{
		Store: store, SigningKey: []byte("secret"), TTL: time.Minute,
		Now: func() time.Time { return now },
	})
	rec := httptest.NewRecorder()
	_ = a.Issue(context.Background(), rec, &principal.Principal{ID: "u1"})
	cookie := rec.Result().Cookies()[0]

	_, err := a.Authenticate(context.Background(), authn.Credentials{Cookies: []string{"session=" + cookie.Value + "x"}})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("tampered code = %v", status.Code(err))
	}

	now = now.Add(2 * time.Minute)
	_, err = a.Authenticate(context.Background(), authn.Credentials{Cookies: []string{"session=" + cookie.Value}})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expired code = %v", status.Code(err))
	}
}

func TestDestroy(t *testing.T) {
	store := memStore{}
	a, _ := session.New(session.Config{Store: store, SigningKey: []byte("secret")})
	rec := httptest.NewRecorder()
	_ = a.Issue(context.Background(), rec, &principal.Principal{ID: "u1"})
	cookie := rec.Result().Cookies()[0]
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(cookie)

	rec = httptest.NewRecorder()
	if err := a.Destroy(context.Background(), rec, req); err != nil {
		t.Fatal(err)
	}
	if len(store) != 0 {
		t.Fatalf("store not empty: %+v", store)
	}
}
