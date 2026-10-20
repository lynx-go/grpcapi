// Package admin 在认证成功后从独立 admin store 补充后台角色与停用标记。
//
// admin 角色写入独立的 admin_roles claim，不混入普通 roles，避免
// 「JWT 带了 admin role 就自动成为后台管理员」的权限混淆。
package admin

import (
	"context"
	"errors"
	"fmt"

	"github.com/lynx-go/grpcapi/authn"
	"github.com/lynx-go/grpcapi/principal"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrNotFound 表示该主体没有 admin 记录。
var ErrNotFound = errors.New("admin: not found")

// Admin 是 admin store 的记录。
type Admin struct {
	Roles     []string
	Suspended bool
	Attrs     map[string]string
}

// Store 是 admin 存储抽象。
type Store interface {
	Get(ctx context.Context, principalID string) (*Admin, error)
}

// Config 是 Enricher 配置。
type Config struct {
	Store Store
	// Claim 默认 "admin_roles"。
	Claim string
	// SuspendedClaim 默认 "admin_suspended"。
	SuspendedClaim string
}

// Enricher 实现 authn.Enricher。
type Enricher struct {
	store          Store
	claim          string
	suspendedClaim string
}

// New 构造 admin Enricher。
func New(cfg Config) (*Enricher, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("admin: Store is nil")
	}
	if cfg.Claim == "" {
		cfg.Claim = "admin_roles"
	}
	if cfg.SuspendedClaim == "" {
		cfg.SuspendedClaim = "admin_suspended"
	}
	return &Enricher{store: cfg.Store, claim: cfg.Claim, suspendedClaim: cfg.SuspendedClaim}, nil
}

// Name 实现 authn.Enricher。
func (e *Enricher) Name() string { return "admin" }

// Enrich 实现 authn.Enricher。
func (e *Enricher) Enrich(ctx context.Context, p *principal.Principal) error {
	if p == nil {
		return nil
	}
	info, err := e.store.Get(ctx, p.ID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return status.Error(codes.Unavailable, "admin store unavailable")
	}
	if info == nil {
		return nil
	}
	if len(info.Roles) > 0 {
		if p.Claims == nil {
			p.Claims = make(map[string][]string)
		}
		p.Claims[e.claim] = union(p.Claims[e.claim], info.Roles)
	}
	if info.Suspended {
		if p.Claims == nil {
			p.Claims = make(map[string][]string)
		}
		p.Claims[e.suspendedClaim] = union(p.Claims[e.suspendedClaim], []string{"true"})
	}
	if len(info.Attrs) > 0 {
		if p.Attrs == nil {
			p.Attrs = make(map[string]string)
		}
		for k, v := range info.Attrs {
			if _, exists := p.Attrs[k]; !exists {
				p.Attrs[k] = v
			}
		}
	}
	return nil
}

func union(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, v := range append(append([]string(nil), a...), b...) {
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

var _ authn.Enricher = (*Enricher)(nil)
