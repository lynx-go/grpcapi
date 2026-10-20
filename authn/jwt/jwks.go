package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// JWKS 是远程 JWKS 的缓存与 jwtlib.KeyFunc 适配器。
type JWKS struct {
	URL             string
	Client          *http.Client
	RefreshInterval time.Duration

	mu        sync.Mutex
	keys      map[string]any
	fetchedAt time.Time
}

// NewJWKS 构造 JWKS key provider；URL 通常来自 OIDC discovery 的 jwks_uri。
func NewJWKS(url string) *JWKS {
	return &JWKS{
		URL:             url,
		Client:          &http.Client{Timeout: 5 * time.Second},
		RefreshInterval: 15 * time.Minute,
	}
}

// KeyFunc 实现 jwtlib.KeyFunc。
func (j *JWKS) KeyFunc(token *jwtlib.Token) (any, error) {
	keys, err := j.keysCached()
	if err != nil {
		return nil, err
	}
	kid, _ := token.Header["kid"].(string)
	if kid != "" {
		if key, ok := keys[kid]; ok {
			return key, nil
		}
		return nil, status.Error(codes.Unauthenticated, "unknown jwt kid")
	}
	if len(keys) == 1 {
		for _, key := range keys {
			return key, nil
		}
	}
	return nil, status.Error(codes.Unauthenticated, "jwt kid is required")
}

func (j *JWKS) keysCached() (map[string]any, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	now := time.Now()
	if len(j.keys) > 0 && now.Sub(j.fetchedAt) < j.RefreshInterval {
		return j.keys, nil
	}
	keys, err := j.fetch()
	if err != nil {
		if len(j.keys) > 0 {
			return j.keys, nil // 刷新失败时使用旧缓存
		}
		return nil, err
	}
	j.keys = keys
	j.fetchedAt = now
	return keys, nil
}

func (j *JWKS) fetch() (map[string]any, error) {
	if j.URL == "" {
		return nil, status.Error(codes.Internal, "jwt: JWKS URL is empty")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.URL, nil)
	if err != nil {
		return nil, status.Error(codes.Internal, "jwt: build JWKS request")
	}
	client := j.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "jwt: fetch JWKS")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, status.Errorf(codes.Unavailable, "jwt: JWKS status %d", resp.StatusCode)
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, status.Error(codes.Unavailable, "jwt: decode JWKS")
	}
	out := make(map[string]any, len(set.Keys))
	for i, k := range set.Keys {
		key, err := k.publicKey()
		if err != nil {
			continue
		}
		kid := k.Kid
		if kid == "" {
			kid = fmt.Sprintf("key-%d", i)
		}
		out[kid] = key
	}
	if len(out) == 0 {
		return nil, status.Error(codes.Unavailable, "jwt: JWKS has no usable keys")
	}
	return out, nil
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (k jwk) publicKey() (any, error) {
	switch k.Kty {
	case "RSA":
		n, err := b64BigInt(k.N)
		if err != nil {
			return nil, err
		}
		e, err := b64BigInt(k.E)
		if err != nil {
			return nil, err
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case "EC":
		curve := curveFor(k.Crv)
		if curve == nil {
			return nil, fmt.Errorf("unsupported curve %q", k.Crv)
		}
		x, err := b64BigInt(k.X)
		if err != nil {
			return nil, err
		}
		y, err := b64BigInt(k.Y)
		if err != nil {
			return nil, err
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	default:
		return nil, fmt.Errorf("unsupported kty %q", k.Kty)
	}
}

func b64BigInt(s string) (*big.Int, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(raw), nil
}

func curveFor(name string) elliptic.Curve {
	switch name {
	case "P-256":
		return elliptic.P256()
	case "P-384":
		return elliptic.P384()
	case "P-521":
		return elliptic.P521()
	default:
		return nil
	}
}
