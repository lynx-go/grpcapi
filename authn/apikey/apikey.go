// Package apikey 提供 API key 认证参考实现：key 哈希查找 + scope 注入。
//
// 项目提供 Store（DB/缓存），库负责 key 提取、哈希、过期/吊销检查、
// Principal 构造与错误语义。
package apikey

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lynx-go/grpcapi/authn"
	"github.com/lynx-go/grpcapi/principal"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrNotFound 表示 key 不存在；Store 应返回它以便区分「无此 key」与后端故障。
var ErrNotFound = errors.New("apikey: not found")

// Key 是 Store 返回的 key 元数据。
type Key struct {
	ID          string
	PrincipalID string
	Scopes      []string
	ExpiresAt   time.Time // 零值 = 永不过期
	Revoked     bool
	Claims      map[string][]string // 可选附加 claim
}

// Active 报告 key 在 now 时点是否有效。
func (k *Key) Active(now time.Time) bool {
	if k == nil || k.Revoked {
		return false
	}
	return k.ExpiresAt.IsZero() || now.Before(k.ExpiresAt)
}

// Store 是 key 存储抽象；Lookup 入参是哈希后的 key。
type Store interface {
	Lookup(ctx context.Context, hash string) (*Key, error)
}

// Config 是认证器配置。
type Config struct {
	Store Store
	// Headers 是候选 header 名；默认 x-api-key。
	Headers []string
	// Prefix 非空时要求 key 带该前缀；不匹配视为「不认识」。
	Prefix string
	// Hash 默认 SHA-256 hex。
	Hash func(string) string
	// Now 默认 time.Now（测试注入）。
	Now func() time.Time
}

// Authenticator 实现 authn.Authenticator。
type Authenticator struct {
	cfg Config
}

// New 构造 API key 认证器。
func New(cfg Config) (*Authenticator, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("apikey: Store is nil")
	}
	if len(cfg.Headers) == 0 {
		cfg.Headers = []string{"x-api-key"}
	}
	if cfg.Hash == nil {
		cfg.Hash = Hash
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Authenticator{cfg: cfg}, nil
}

// Name 实现 authn.Authenticator。
func (a *Authenticator) Name() string { return "apikey" }

// Authenticate 实现 authn.Authenticator。
func (a *Authenticator) Authenticate(ctx context.Context, c authn.Credentials) (*principal.Principal, error) {
	raw := c.APIKey()
	if raw == "" {
		for _, h := range a.cfg.Headers {
			if vs := c.Metadata.Get(strings.ToLower(h)); len(vs) > 0 {
				raw = vs[0]
				break
			}
		}
	}
	if raw == "" {
		return nil, nil
	}
	if a.cfg.Prefix != "" && !strings.HasPrefix(raw, a.cfg.Prefix) {
		return nil, nil
	}
	key, err := a.cfg.Store.Lookup(ctx, a.cfg.Hash(raw))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, status.Error(codes.Unauthenticated, "invalid api key")
		}
		return nil, status.Error(codes.Unavailable, "api key store unavailable")
	}
	if !key.Active(a.cfg.Now()) {
		return nil, status.Error(codes.Unauthenticated, "api key expired or revoked")
	}
	claims := make(map[string][]string, len(key.Claims)+1)
	for k, vs := range key.Claims {
		claims[k] = append([]string(nil), vs...)
	}
	if len(key.Scopes) > 0 {
		claims["scopes"] = append([]string(nil), key.Scopes...)
	}
	return &principal.Principal{
		ID:     key.PrincipalID,
		Kind:   principal.KindAPIKey,
		Claims: claims,
		Attrs:  map[string]string{"api_key_id": key.ID},
	}, nil
}

// Hash 是默认 key 哈希：SHA-256 hex。
func Hash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
