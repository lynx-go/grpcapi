// Package contextx 提供 gRPC 请求上下文的通用存取件：客户端信息
// （ClientInfo）与审计可变槽（AuditTrail）。
//
// 与项目内 contexts 包的关系（DESIGN §6 裁决 6）：本包只承载与项目
// 标识符零耦合的通用子集；项目侧以门面（contexts 薄层）委托到本包。
package contextx

import "context"

// ClientInfo 捕获请求来源信息，用于会话与审计记录。
// IP 为 string：解析策略（trusted proxies、GeoIP 等）由项目决定，
// 库只负责在 ctx 中搬运结果。
type ClientInfo struct {
	IP        string
	UserAgent string
}

type ctxKey int

const (
	ctxKeyClientInfo ctxKey = iota
	ctxKeyAuditTrail
)

// WithClientInfo 将客户端信息注入 ctx（clientInfo 拦截器在链首调用）。
func WithClientInfo(ctx context.Context, ci ClientInfo) context.Context {
	return context.WithValue(ctx, ctxKeyClientInfo, ci)
}

// ClientInfoFrom 取出客户端信息；ctx 中不存在时 ok 为 false。
func ClientInfoFrom(ctx context.Context) (ClientInfo, bool) {
	v, ok := ctx.Value(ctxKeyClientInfo).(ClientInfo)
	return v, ok
}
