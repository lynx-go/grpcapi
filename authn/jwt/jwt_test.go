package jwt_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
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

func jwksServer(t *testing.T, keys any, count *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if count != nil {
			count.Add(1)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	}))
}

func newJWKSAuth(t *testing.T, srvURL string, methods ...string) *jwt.Authenticator {
	t.Helper()
	a, err := jwt.New(jwt.Config{
		KeyFunc:                jwt.NewJWKS(srvURL).KeyFunc,
		ValidMethods:           methods,
		AllowMissingExpiration: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestJWKSECKey(t *testing.T) {
	// EC P-256 JWK 解析与 ES256 验签。
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv := jwksServer(t, []map[string]any{{
		"kty": "EC",
		"kid": "ec1",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(priv.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(priv.Y.Bytes()),
	}}, nil)
	defer srv.Close()

	token := jwtlib.NewWithClaims(jwtlib.SigningMethodES256, jwtlib.MapClaims{
		"sub": "u1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	token.Header["kid"] = "ec1"
	signed, err := token.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	p, err := newJWKSAuth(t, srv.URL, "ES256").
		Authenticate(context.Background(), authn.Credentials{Bearer: []string{signed}})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if p.ID != "u1" {
		t.Fatalf("principal = %+v", p)
	}
}

func TestJWKSUnsupportedKeySkipped(t *testing.T) {
	// 不可用 kty（如 oct 对称密钥）必须跳过，不能阻断同 set 里的 RSA key。
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv := jwksServer(t, []map[string]any{
		{"kty": "oct", "kid": "sym", "k": "not-a-public-key"},
		{
			"kty": "RSA",
			"kid": "k1",
			"n":   base64.RawURLEncoding.EncodeToString(priv.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes()),
		},
	}, nil)
	defer srv.Close()

	token := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, jwtlib.MapClaims{
		"sub": "u1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	token.Header["kid"] = "k1"
	signed, _ := token.SignedString(priv)
	p, err := newJWKSAuth(t, srv.URL, "RS256").
		Authenticate(context.Background(), authn.Credentials{Bearer: []string{signed}})
	if err != nil || p.ID != "u1" {
		t.Fatalf("Authenticate = %+v, %v (usable key must survive unusable siblings)", p, err)
	}
}

func TestAlgorithmConfusionRejected(t *testing.T) {
	// 经典 RS256→HS256 混淆：把 RSA 公钥当 HMAC secret 签 HS256 token，
	// 即便签名碰巧可验也必须被 ValidMethods 白名单拒绝。
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	confused := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, jwtlib.MapClaims{
		"sub": "u1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	signed, err := confused.SignedString(pubDER)
	if err != nil {
		t.Fatal(err)
	}
	a, err := jwt.New(jwt.Config{
		KeyFunc:      func(*jwtlib.Token) (any, error) { return &priv.PublicKey, nil },
		ValidMethods: []string{"RS256"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Authenticate(context.Background(), authn.Credentials{Bearer: []string{signed}}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated (alg confusion must fail)", status.Code(err))
	}

	// alg=none 同样拒绝。
	none := jwtlib.NewWithClaims(jwtlib.SigningMethodNone, jwtlib.MapClaims{
		"sub": "u1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	noneSigned, err := none.SignedString(jwtlib.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Authenticate(context.Background(), authn.Credentials{Bearer: []string{noneSigned}}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated (alg=none must fail)", status.Code(err))
	}
}

func TestMissingExpirationRejected(t *testing.T) {
	key := []byte("secret")
	signed, _ := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, jwtlib.MapClaims{
		"sub": "u1",
		// 无 exp。
	}).SignedString(key)
	a, _ := jwt.New(jwt.Config{
		KeyFunc:                func(*jwtlib.Token) (any, error) { return key, nil },
		ValidMethods:           []string{"HS256"},
		AllowMissingExpiration: false,
	})
	if _, err := a.Authenticate(context.Background(), authn.Credentials{Bearer: []string{signed}}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated (missing exp must fail by default)", status.Code(err))
	}
}

func TestJWKSConcurrentRefreshCoalesces(t *testing.T) {
	// 缓存过期/冷启动时并发 KeyFunc 只应触发一次网络刷新（刷新已移出
	// keys 锁，其余请求经刷新锁双检复用结果），不再把并发认证串行化成
	// N 次 fetch。
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	var fetches atomic.Int32
	srv := jwksServer(t, []map[string]any{{
		"kty": "RSA",
		"kid": "k1",
		"n":   base64.RawURLEncoding.EncodeToString(priv.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes()),
	}}, &fetches)
	defer srv.Close()

	token := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, jwtlib.MapClaims{
		"sub": "u1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	token.Header["kid"] = "k1"
	signed, _ := token.SignedString(priv)

	a := newJWKSAuth(t, srv.URL, "RS256")
	const n = 16
	errs := make([]error, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			_, errs[i] = a.Authenticate(context.Background(), authn.Credentials{Bearer: []string{signed}})
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	if got := fetches.Load(); got != 1 {
		t.Fatalf("JWKS fetches = %d, want 1 (concurrent refresh must coalesce)", got)
	}
}

func TestJWKSEd25519(t *testing.T) {
	// kty=OKP / Crv=Ed25519：解析与 EdDSA 验签。
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv := jwksServer(t, []map[string]any{{
		"kty": "OKP",
		"kid": "ed1",
		"crv": "Ed25519",
		"x":   base64.RawURLEncoding.EncodeToString(pub),
	}}, nil)
	defer srv.Close()

	token := jwtlib.NewWithClaims(jwtlib.SigningMethodEdDSA, jwtlib.MapClaims{
		"sub": "u1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	token.Header["kid"] = "ed1"
	signed, err := token.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	p, err := newJWKSAuth(t, srv.URL, "EdDSA").
		Authenticate(context.Background(), authn.Credentials{Bearer: []string{signed}})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if p.ID != "u1" {
		t.Fatalf("principal = %+v", p)
	}

	// 坏曲线的 OKP key 被跳过：set 里只剩 RSA 时照常工作。
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv2 := jwksServer(t, []map[string]any{
		{"kty": "OKP", "kid": "bad", "crv": "P-256", "x": "aaa"},
		{
			"kty": "RSA",
			"kid": "k1",
			"n":   base64.RawURLEncoding.EncodeToString(rsaPriv.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaPriv.E)).Bytes()),
		},
	}, nil)
	defer srv2.Close()
	rsaToken := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, jwtlib.MapClaims{
		"sub": "u2",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	rsaToken.Header["kid"] = "k1"
	rsaSigned, _ := rsaToken.SignedString(rsaPriv)
	p, err = newJWKSAuth(t, srv2.URL, "RS256").
		Authenticate(context.Background(), authn.Credentials{Bearer: []string{rsaSigned}})
	if err != nil || p.ID != "u2" {
		t.Fatalf("Authenticate = %+v, %v (bad OKP must be skipped)", p, err)
	}
}
