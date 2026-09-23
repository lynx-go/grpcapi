package contextx

import (
	"context"
	"maps"
	"sync"
)

// AuditTrail 是审计信息的可变槽：audit 拦截器在请求 ctx 中预置
// （WithAuditTrail），handler 内的 SetAuditResource/SetAuditMetadata
// 通过 ctx 链查找并原地写入，拦截器在 handler 返回后经 AuditTrailFrom
// 读取累计结果。
//
// 为什么需要可变槽：context 值不可变，跨函数边界（拦截器 → handler →
// 用例层）共享“执行过程中逐步产生的审计事实”必须以指针为载体在原地
// 累积，否则后写者只能派生新 ctx，上游永远读不到。
type AuditTrail struct {
	mu       sync.Mutex
	resource string
	metadata map[string]string
}

// NewAuditTrail 构造空审计槽。零值 AuditTrail 同样可用。
func NewAuditTrail() *AuditTrail {
	return &AuditTrail{}
}

// WithAuditTrail 将审计槽预置进 ctx（仅由 audit 拦截器调用）。
func WithAuditTrail(ctx context.Context, t *AuditTrail) context.Context {
	return context.WithValue(ctx, ctxKeyAuditTrail, t)
}

// AuditTrailFrom 取出 ctx 中的审计槽；不存在时返回 nil。
func AuditTrailFrom(ctx context.Context) *AuditTrail {
	t, _ := ctx.Value(ctxKeyAuditTrail).(*AuditTrail)
	return t
}

// SetAuditResource 记录本请求作用的资源标识（如被删除对象的 id），
// 供 handler 返回后的 audit 拦截器落审计行。ctx 链中无审计槽时为
// no-op（直调场景），不派生新 ctx。
func SetAuditResource(ctx context.Context, resource string) {
	if t, ok := ctx.Value(ctxKeyAuditTrail).(*AuditTrail); ok {
		t.setResource(resource)
	}
}

// SetAuditMetadata 记录一个结构化审计扩展键（如 changes 的
// before/after 摘要）。ctx 链中无审计槽时为 no-op。并发安全。
func SetAuditMetadata(ctx context.Context, key, value string) {
	if t, ok := ctx.Value(ctxKeyAuditTrail).(*AuditTrail); ok {
		t.setMetadata(key, value)
	}
}

func (t *AuditTrail) setResource(resource string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.resource = resource
}

func (t *AuditTrail) setMetadata(key, value string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.metadata == nil {
		t.metadata = make(map[string]string)
	}
	t.metadata[key] = value
}

// Resource 返回累计的资源标识。nil 接收者返回空串。
func (t *AuditTrail) Resource() string {
	if t == nil {
		return ""
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.resource
}

// Metadata 返回累计元数据的副本（隔离调用方与并发写入）；无内容时
// 返回 nil。nil 接收者返回 nil。
func (t *AuditTrail) Metadata() map[string]string {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.metadata) == 0 {
		return nil
	}
	out := make(map[string]string, len(t.metadata))
	maps.Copy(out, t.metadata)
	return out
}
