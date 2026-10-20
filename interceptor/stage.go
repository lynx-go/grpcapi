package interceptor

import "google.golang.org/grpc"

// StageOf 构造自定义 Stage；name/order 由调用方决定。
func StageOf(name string, order int, unary grpc.UnaryServerInterceptor, stream grpc.StreamServerInterceptor) Stage {
	return Stage{Name: name, Order: order, Unary: unary, Stream: stream}
}

// RecoveryStage 构造 panic 恢复 Stage。
func RecoveryStage(opts RecoveryOptions) Stage {
	r := NewRecovery(opts)
	return Stage{Name: StageRecovery, Order: OrderRecovery, Unary: r.Unary(), Stream: r.Stream()}
}

// RequestIDStage 构造 request ID Stage。
func RequestIDStage(opts RequestIDOptions) Stage {
	r := NewRequestID(opts)
	return Stage{Name: StageRequestID, Order: OrderRequestID, Unary: r.Unary(), Stream: r.Stream()}
}

// ClientInfoStage 构造 clientInfo Stage。
func ClientInfoStage(c *ClientInfoInterceptor) Stage {
	st := Stage{Name: StageClientInfo, Order: OrderClientInfo}
	if c != nil {
		st.Unary = c.Unary()
		st.Stream = c.Stream()
	}
	return st
}

// AuthnStage 构造认证 Stage（实现由 authn 模块提供）。
func AuthnStage(unary grpc.UnaryServerInterceptor, stream grpc.StreamServerInterceptor) Stage {
	return Stage{Name: StageAuthn, Order: OrderAuthn, Unary: unary, Stream: stream}
}

// AuthzStage 构造授权 Stage（通常传 authz.Interceptor 的 Unary/Stream）。
func AuthzStage(unary grpc.UnaryServerInterceptor, stream grpc.StreamServerInterceptor) Stage {
	return Stage{Name: StageAuthz, Order: OrderAuthz, Unary: unary, Stream: stream}
}

// RateLimitStage 构造限流 Stage。
func RateLimitStage(unary grpc.UnaryServerInterceptor, stream grpc.StreamServerInterceptor) Stage {
	return Stage{Name: StageRateLimit, Order: OrderRateLimit, Unary: unary, Stream: stream}
}

// AuditStage 构造审计 Stage。
func AuditStage(unary grpc.UnaryServerInterceptor, stream grpc.StreamServerInterceptor) Stage {
	return Stage{Name: StageAudit, Order: OrderAudit, Unary: unary, Stream: stream}
}

// UsageStage 构造用量 Stage。
func UsageStage(unary grpc.UnaryServerInterceptor, stream grpc.StreamServerInterceptor) Stage {
	return Stage{Name: StageUsage, Order: OrderUsage, Unary: unary, Stream: stream}
}

// ValidateStage 构造校验 Stage。
func ValidateStage(v *ValidateInterceptor) Stage {
	st := Stage{Name: StageValidate, Order: OrderValidate}
	if v != nil {
		st.Unary = v.Unary()
		st.Stream = v.Stream()
	}
	return st
}
