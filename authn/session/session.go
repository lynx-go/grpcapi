// Package session 提供 cookie session 认证参考实现。
//
// cookie 只携带随机会话 ID + HMAC 签名；业务 claims 存在 Store 中，不放进
// cookie。session 认证强制要求 CSRF（RequiresCSRF 返回 true）。
package session

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lynx-go/grpcapi/authn"
	"github.com/lynx-go/grpcapi/principal"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrNotFound 表示 session 不存在/已过期。
var ErrNotFound = errors.New("session: not found")

// Session 是服务端保存的会话记录。
type Session struct {
	ID          string
	PrincipalID string
	Kind        string
	Claims      map[string][]string
	Attrs       map[string]string
	ExpiresAt   time.Time
}

// Store 是 session 存储抽象。
type Store interface {
	Get(ctx context.Context, id string) (*Session, error)
	Create(ctx context.Context, s *Session) error
	Touch(ctx context.Context, id string, ttl time.Duration) error
	Delete(ctx context.Context, id string) error
}

// Config 是 session 认证器配置。
type Config struct {
	// CookieName 默认 "session"。
	CookieName string
	Store      Store
	// SigningKey 必填；用于 HMAC 签名。
	SigningKey []byte
	// TTL 默认 24h。
	TTL time.Duration
	// Path 默认 "/"。
	Path     string
	Secure   bool
	SameSite http.SameSite
	Now      func() time.Time
}

func (c Config) normalize() Config {
	if c.CookieName == "" {
		c.CookieName = "session"
	}
	if c.TTL == 0 {
		c.TTL = 24 * time.Hour
	}
	if c.Path == "" {
		c.Path = "/"
	}
	if c.SameSite == 0 {
		c.SameSite = http.SameSiteLaxMode
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c
}

// Authenticator 实现 authn.Authenticator。
type Authenticator struct {
	cfg Config
}

// New 构造 session 认证器。
func New(cfg Config) (*Authenticator, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("session: Store is nil")
	}
	if len(cfg.SigningKey) == 0 {
		return nil, fmt.Errorf("session: SigningKey is empty")
	}
	return &Authenticator{cfg: cfg.normalize()}, nil
}

// Name 实现 authn.Authenticator。
func (a *Authenticator) Name() string { return "session" }

// RequiresCSRF 供 server 强制配置 CSRF。
func (a *Authenticator) RequiresCSRF() bool { return true }

// Issue 创建 session 并设置 cookie；登录成功后调用。
func (a *Authenticator) Issue(ctx context.Context, w http.ResponseWriter, p *principal.Principal) error {
	if p == nil {
		return fmt.Errorf("session: principal is nil")
	}
	id, err := newID()
	if err != nil {
		return err
	}
	now := a.cfg.Now()
	s := &Session{
		ID:          id,
		PrincipalID: p.ID,
		Kind:        p.Kind,
		Claims:      cloneClaims(p.Claims),
		Attrs:       cloneAttrs(p.Attrs),
		ExpiresAt:   now.Add(a.cfg.TTL),
	}
	if err := a.cfg.Store.Create(ctx, s); err != nil {
		return fmt.Errorf("session: create: %w", err)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     a.cfg.CookieName,
		Value:    a.sign(id),
		Path:     a.cfg.Path,
		Expires:  s.ExpiresAt,
		MaxAge:   int(a.cfg.TTL.Seconds()),
		Secure:   a.cfg.Secure,
		HttpOnly: true,
		SameSite: a.cfg.SameSite,
	})
	return nil
}

// Authenticate 实现 authn.Authenticator。
func (a *Authenticator) Authenticate(ctx context.Context, c authn.Credentials) (*principal.Principal, error) {
	raw := c.Cookie(a.cfg.CookieName)
	if raw == "" {
		return nil, nil
	}
	id, ok := a.verify(raw)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "invalid session")
	}
	s, err := a.cfg.Store.Get(ctx, id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, status.Error(codes.Unauthenticated, "session not found")
		}
		return nil, status.Error(codes.Unavailable, "session store unavailable")
	}
	if s == nil || !a.cfg.Now().Before(s.ExpiresAt) {
		return nil, status.Error(codes.Unauthenticated, "session expired")
	}
	_ = a.cfg.Store.Touch(ctx, id, a.cfg.TTL)
	kind := s.Kind
	if kind == "" {
		kind = principal.KindUser
	}
	return &principal.Principal{
		ID:     s.PrincipalID,
		Kind:   kind,
		Claims: cloneClaims(s.Claims),
		Attrs:  cloneAttrs(s.Attrs),
	}, nil
}

// Destroy 删除当前 session 并清除 cookie。
func (a *Authenticator) Destroy(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	if ck, err := r.Cookie(a.cfg.CookieName); err == nil {
		if id, ok := a.verify(ck.Value); ok {
			_ = a.cfg.Store.Delete(ctx, id)
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     a.cfg.CookieName,
		Value:    "",
		Path:     a.cfg.Path,
		MaxAge:   -1,
		Secure:   a.cfg.Secure,
		HttpOnly: true,
		SameSite: a.cfg.SameSite,
	})
	return nil
}

func (a *Authenticator) sign(id string) string {
	mac := hmac.New(sha256.New, a.cfg.SigningKey)
	mac.Write([]byte(id))
	return id + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (a *Authenticator) verify(value string) (string, bool) {
	id, sig, ok := strings.Cut(value, ".")
	if !ok || id == "" || sig == "" {
		return "", false
	}
	mac := hmac.New(sha256.New, a.cfg.SigningKey)
	mac.Write([]byte(id))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(sig), []byte(want)) != 1 {
		return "", false
	}
	return id, true
}

func newID() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("session: random id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func cloneClaims(in map[string][]string) map[string][]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string][]string, len(in))
	for k, vs := range in {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

func cloneAttrs(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
