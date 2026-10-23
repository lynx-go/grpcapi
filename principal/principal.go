// Package principal 定义 API 请求中的身份主体（Principal）及其 context 存取。
//
// Principal 是认证器的产物、授权器的输入：认证器负责把 JWT/session/API key
// 变成 Principal；授权器只消费 Principal 的 Kind/Claims/Attrs，不关心凭证
// 的具体形态。本包零外部依赖，便于 domain 层直接引用。
package principal

import "context"

// 常用身份类型。项目可以自定义其他字符串；库只在约定默认注册表时使用这些值。
const (
	KindUser    = "user"
	KindService = "service"
	KindAPIKey  = "api_key"
	KindAdmin   = "admin"
)

// Principal 是一次请求的身份投影。
type Principal struct {
	// ID 是稳定主体标识（用户 ID、服务名、API key ID 等）。
	ID string
	// Kind 是身份类型（user/service/api_key/项目自定义）。
	Kind string
	// Claims 是多值 claim 集合（roles/scopes/permissions/tenant/aud/admin_roles 等）。
	Claims map[string][]string
	// Attrs 是单值扩展属性（如 admin_suspended、email）。
	Attrs map[string]string
	// Raw 保留认证器的原始凭证对象（*jwt.Token、*x509.Certificate 等），
	// 仅供项目自定义 Decider/Kind 使用；库本身不解释。
	Raw any
}

type ctxKey struct{}

// With 将 Principal 注入 ctx。p 为 nil 时返回原 ctx。
func With(ctx context.Context, p *Principal) context.Context {
	if p == nil {
		return ctx
	}
	return context.WithValue(ctx, ctxKey{}, p)
}

// From 取出 ctx 中的 Principal；不存在时 ok 为 false。
func From(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(*Principal)
	return p, ok
}

// MustFrom 取出 Principal；缺失时 panic。Must 前缀遵循 Go 惯例：仅用于
// 不变量已由上游保证的路径（如 authn 拦截器之后的 handler/中间件）；
// 可能缺失时用 From 拿 ok 语义。
func MustFrom(ctx context.Context) *Principal {
	p, ok := From(ctx)
	if !ok {
		panic("principal: MustFrom called on a context without a Principal")
	}
	return p
}

// Clone 返回深拷贝；nil 接收者返回 nil。认证器可以用它避免调用方修改内部状态。
func (p *Principal) Clone() *Principal {
	if p == nil {
		return nil
	}
	out := &Principal{
		ID:   p.ID,
		Kind: p.Kind,
		Raw:  p.Raw,
	}
	if len(p.Claims) > 0 {
		out.Claims = make(map[string][]string, len(p.Claims))
		for k, vs := range p.Claims {
			out.Claims[k] = append([]string(nil), vs...)
		}
	}
	if len(p.Attrs) > 0 {
		out.Attrs = make(map[string]string, len(p.Attrs))
		for k, v := range p.Attrs {
			out.Attrs[k] = v
		}
	}
	return out
}

// Claim 返回 claim 的副本；不存在或 nil 接收者返回 nil。
func (p *Principal) Claim(name string) []string {
	if p == nil {
		return nil
	}
	vs := p.Claims[name]
	if len(vs) == 0 {
		return nil
	}
	return append([]string(nil), vs...)
}

// HasClaim 报告 claim 是否至少包含 values 中的一个；values 为空时表示
// claim 存在且非空。
func (p *Principal) HasClaim(name string, values ...string) bool {
	return p.matchClaim(name, false, values...)
}

// HasAllClaims 报告 claim 是否包含全部 values；values 为空时等价于 HasClaim。
func (p *Principal) HasAllClaims(name string, values ...string) bool {
	return p.matchClaim(name, true, values...)
}

func (p *Principal) matchClaim(name string, all bool, values ...string) bool {
	if p == nil {
		return false
	}
	have := p.Claims[name]
	if len(values) == 0 {
		return len(have) > 0
	}
	set := make(map[string]struct{}, len(have))
	for _, v := range have {
		set[v] = struct{}{}
	}
	matched := 0
	for _, v := range values {
		if _, ok := set[v]; ok {
			matched++
			if !all {
				return true
			}
		}
	}
	return all && matched == len(values)
}

// Attribute 返回单值属性；不存在返回空串。
func (p *Principal) Attribute(name string) string {
	if p == nil {
		return ""
	}
	return p.Attrs[name]
}

// HasKind 报告身份类型是否在 kinds 中。
func (p *Principal) HasKind(kinds ...string) bool {
	if p == nil {
		return false
	}
	for _, k := range kinds {
		if p.Kind == k {
			return true
		}
	}
	return false
}
