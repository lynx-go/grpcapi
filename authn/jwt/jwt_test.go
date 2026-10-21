package jwt_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/lynx-go/grpcapi/authn"
	"github.com/lynx-go/grpcapi/authn/jwt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestHMACParser(t *testing.T) {
	key := []byte("secret")
	signed, err := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, jwtlib.MapClaims{
		"sub":   "u1",
		"roles": []string{"admin"},
		"exp":   time.Now().Add(time.Hour).Unix(),
	}).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	a, err := jwt.New(jwt.Config{
		KeyFunc:                func(*jwtlib.Token) (any, error) { return key, nil },
		ValidMethods:           []string{"HS256"},
		AllowMissingExpiration: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := a.Authenticate(context.Background(), authn.Credentials{Bearer: []string{signed}})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if p.ID != "u1" || len(p.Claim("roles")) != 1 || p.Claim("roles")[0] != "admin" {
		t.Fatalf("principal = %+v", p)
	}

	if p, err := a.Authenticate(context.Background(), authn.Credentials{}); err != nil || p != nil {
		t.Fatalf("no token = %+v, %v", p, err)
	}
}

func TestExpiredToken(t *testing.T) {
	key := []byte("secret")
	signed, _ := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, jwtlib.MapClaims{
		"sub": "u1",
		"exp": time.Now().Add(-time.Hour).Unix(),
	}).SignedString(key)
	a, _ := jwt.New(jwt.Config{
		KeyFunc:                func(*jwtlib.Token) (any, error) { return key, nil },
		ValidMethods:           []string{"HS256"},
		AllowMissingExpiration: false,
	})
	_, err := a.Authenticate(context.Background(), authn.Credentials{Bearer: []string{signed}})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", status.Code(err))
	}
}

func TestKindClaimCannotOverrideConfig(t *testing.T) {
	// kind 只由服务端配置决定：token 自带 kind claim 不得切换 principal
	// kind（共享 IdP 下可影响的 claim 是提权面）。
	key := []byte("secret")
	signed, _ := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, jwtlib.MapClaims{
		"sub":  "u1",
		"kind": "server",
		"exp":  time.Now().Add(time.Hour).Unix(),
	}).SignedString(key)
	a, err := jwt.New(jwt.Config{
		KeyFunc:                func(*jwtlib.Token) (any, error) { return key, nil },
		ValidMethods:           []string{"HS256"},
		AllowMissingExpiration: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := a.Authenticate(context.Background(), authn.Credentials{Bearer: []string{signed}})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if p.Kind != "user" {
		t.Fatalf("kind = %q, want server-configured %q (token kind claim must be ignored)", p.Kind, "user")
	}
}

func TestJWKS(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	set := map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"kid": "k1",
			"n":   base64.RawURLEncoding.EncodeToString(priv.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes()),
		}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(set)
	}))
	defer srv.Close()

	token := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, jwtlib.MapClaims{
		"sub": "u1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	token.Header["kid"] = "k1"
	signed, err := token.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}

	jwks := jwt.NewJWKS(srv.URL)
	a, err := jwt.New(jwt.Config{
		KeyFunc:                jwks.KeyFunc,
		ValidMethods:           []string{"RS256"},
		AllowMissingExpiration: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := a.Authenticate(context.Background(), authn.Credentials{Bearer: []string{signed}})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if p.ID != "u1" {
		t.Fatalf("principal = %+v", p)
	}
}
