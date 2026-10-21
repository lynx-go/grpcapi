package gateway

import (
	"context"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc/metadata"
)

// MuxOptions 是 NewMux 的装配选项，零值即安全默认。
type MuxOptions struct {
	// ErrorEncoder 编码 gRPC 错误为 HTTP 响应；nil 时回落
	// DefaultErrorEncoder(ErrorOptions{})。
	ErrorEncoder ErrorEncoder

	// Headers 是入/出站 header 策略；零值等效 DefaultHeaderPolicy()。
	// 项目专属放行/直透头在 Allow/Direct 里声明（覆盖默认列表）。
	Headers HeaderPolicy

	// Marshaler 为空时使用 NewMarshaler()（snake_case）。
	Marshaler runtime.Marshaler

	// ServeMuxOptions 追加 runtime.ServeMux 选项。
	ServeMuxOptions []runtime.ServeMuxOption

	// Metadata 是请求 metadata annotator；server 默认用它注入可信 client-ip。
	Metadata func(context.Context, *http.Request) metadata.MD
}

// NewMux 构造 grpc-gateway ServeMux（平移自 torchwood NewGRPCGatewayServer 的
// mux 装配段）：统一错误编码器 + HeaderPolicy 驱动的入/出站 matcher + 三个
// marshaler 槽位（*、*/*、application/json）全部装 NewMarshaler()。
func NewMux(o MuxOptions) *runtime.ServeMux {
	encoder := o.ErrorEncoder
	if encoder == nil {
		encoder = DefaultErrorEncoder(ErrorOptions{})
	}
	marshaler := o.Marshaler
	if marshaler == nil {
		marshaler = NewMarshaler()
	}
	opts := []runtime.ServeMuxOption{
		runtime.WithErrorHandler(NewEncoderErrorHandler(encoder)),
		runtime.WithIncomingHeaderMatcher(IncomingPolicy(o.Headers)),
		runtime.WithOutgoingHeaderMatcher(OutgoingPolicy(o.Headers)),
		runtime.WithMarshalerOption("*", marshaler),
		runtime.WithMarshalerOption("*/*", marshaler),
		runtime.WithMarshalerOption("application/json", marshaler),
	}
	opts = append(opts, o.ServeMuxOptions...)
	if o.Metadata != nil {
		opts = append(opts, runtime.WithMetadata(o.Metadata))
	}
	return runtime.NewServeMux(opts...)
}
