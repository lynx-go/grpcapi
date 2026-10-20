package authz

import "context"

// ResourceResolver 从请求中解析对象级授权资源（owner/tenant/relation 等）。
// 只负责取资源，不做决策；解析失败应按 fail-closed 处理。
type ResourceResolver interface {
	Resolve(ctx context.Context, req Request) (any, error)
}
