package contextx

import "context"

// RequestID 是一次请求的关联标识；由 requestid 拦截器注入 ctx，供日志/审计使用。
type requestIDKey struct{}

// WithRequestID 将 request ID 注入 ctx。
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestIDFrom 取出 request ID；不存在时 ok 为 false。
func RequestIDFrom(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(requestIDKey{}).(string)
	return id, ok
}
