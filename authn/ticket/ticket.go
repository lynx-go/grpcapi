// Package ticket 提供短时单用途票据认证器参考实现。
//
// 场景：EventSource / 浏览器 WebSocket 无法携带 Authorization 头，客户端先
// 以常规凭证向业务端点换取秒级 TTL 的单用途票据，再以 ?ticket= 发起流式
// 请求。提取经 authn.WithQueryTicket 显式开启（HTTP 面）或 x-ticket
// metadata（gRPC 面）。
//
// 安全义务在 Store：票据必须密码学随机、短 TTL、兑换即作废（单用途）；
// 本包只做"取票据 → 兑换 → Principal"的粘合。查询串会经过代理与访问日志，
// 不要把长期凭证放进 query。
package ticket

import (
	"context"
	"fmt"

	"github.com/lynx-go/grpcapi/authn"
	"github.com/lynx-go/grpcapi/principal"
)

// Store 兑换票据。实现语义：
//
//   - (nil, nil)：票据不认识/不属于本认证器，继续尝试下一个认证器；
//   - (nil, error)：票据认识但被拒绝（过期/已用/撤销）或后端故障，立即
//     返回该错误（unauthenticated status）；
//   - (principal, nil)：兑换成功。单用途由实现保证—— Redeem 返回成功后
//     同一票据必须立即作废。
type Store interface {
	Redeem(ctx context.Context, token string) (*principal.Principal, error)
}

// Authenticator 是票据认证器。
type Authenticator struct {
	store Store
}

// New 构造票据认证器；store 为 nil 时 panic（缺 store 的认证器没有安全
// 语义，fail-closed）。
func New(store Store) *Authenticator {
	if store == nil {
		panic("ticket: New requires a non-nil Store")
	}
	return &Authenticator{store: store}
}

// Name 返回认证器名。
func (a *Authenticator) Name() string { return "ticket" }

// Authenticate 兑换请求中的票据；请求不带票据时返回 (nil, nil) 交还链。
func (a *Authenticator) Authenticate(ctx context.Context, c authn.Credentials) (*principal.Principal, error) {
	token := c.Ticket()
	if token == "" {
		return nil, nil
	}
	p, err := a.store.Redeem(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("ticket: redeem: %w", err)
	}
	if p == nil {
		return nil, nil
	}
	return p, nil
}
