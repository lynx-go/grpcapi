package gateway

// v0.2.x 兼容垫片。
//
// v0.3.0 起 gateway 公开 API 冻结至 v1：破坏性变更只允许以新类型/新函数
// 形式加入，不再移动、重命名或删除既有符号。下列符号是 v0.2.1 → v0.3.0
// 收敛时删除的旧形态，按 torchwood 等已迁移消费者的现行用法重建为垫片，
// 行为与 v0.2.1 等价、内部委托新实现；计划 v1.0 移除。新代码不要使用。

import (
	"context"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
)

// ErrorBodyBuilder 由项目实现，承载对客户端的错误契约（库不感知错误体形状）。
//
// Deprecated: 用 ErrorEncoder / ErrorEncoderFunc 完全接管错误体；旧实现可经
// BuilderEncoder 无损适配。
type ErrorBodyBuilder interface {
	Build(code codes.Code, message, errorID string) proto.Message
	MapErrorCode(code codes.Code) any
}

// HTTPOptions 是 v0.2.1 统一错误处理器的行为选项。
//
// Deprecated: 用 ErrorOptions。
type HTTPOptions struct {
	CodeToHTTP       map[codes.Code]int
	SanitizeInternal bool
	Logger           *slog.Logger
}

// BuilderEncoder 把 v0.2.1 ErrorBodyBuilder 适配为 ErrorEncoder：code→HTTP、
// 脱敏与 Retry-After 语义走 ErrorOptions 内核，错误体由 builder 构造
// （proto.Message，经 protojson 序列化）。b 为 nil 时回落默认 map 错误体。
// 迁移期可作为 MuxOptions.ErrorEncoder 直接注入，行为与 v0.2.1 等价。
func BuilderEncoder(b ErrorBodyBuilder, o HTTPOptions) ErrorEncoder {
	opts := ErrorOptions{CodeToHTTP: o.CodeToHTTP, Logger: o.Logger}
	return ErrorEncoderFunc(func(ctx context.Context, err error) ErrorResponse {
		return encodeError(ctx, err, opts, func(code codes.Code, message, errorID string) any {
			if b == nil {
				return map[string]any{"code": opts.codeString(code), "message": message, "error_id": errorID}
			}
			return b.Build(code, message, errorID)
		})
	})
}

// NewErrorHandler 构造 grpc-gateway 统一错误处理器（v0.2.1 形态）。
//
// Deprecated: 用 NewEncoderErrorHandler(BuilderEncoder(b, o))，或直接把
// BuilderEncoder 结果作为 MuxOptions.ErrorEncoder 注入。
func NewErrorHandler(b ErrorBodyBuilder, o HTTPOptions) runtime.ErrorHandlerFunc {
	return NewEncoderErrorHandler(BuilderEncoder(b, o))
}

// IncomingMatcher 构造 grpc-gateway 入站 header matcher（v0.2.1 形态）：
// authorization/x-grpcapi-client-ip 系列恒拒，默认头 + extraAllow 放行，
// 其余回落 grpc-gateway 默认。
//
// Deprecated: 用 IncomingPolicy(HeaderPolicy{Allow: append(默认放行, extraAllow...)})。
func IncomingMatcher(extraAllow ...string) func(string) (string, bool) {
	p := DefaultHeaderPolicy()
	p.Allow = append(p.Allow, extraAllow...)
	return IncomingPolicy(p)
}

// OutgoingMatcher 构造 grpc-gateway 出站 header matcher（v0.2.1 形态）：
// set-cookie + direct 直透，其余加 Grpc-Metadata- 前缀。
//
// Deprecated: 用 OutgoingPolicy(HeaderPolicy{Direct: append(默认直透, direct...)})。
func OutgoingMatcher(direct ...string) func(string) (string, bool) {
	p := DefaultHeaderPolicy()
	p.Direct = append(p.Direct, direct...)
	return OutgoingPolicy(p)
}
