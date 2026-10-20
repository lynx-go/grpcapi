package gateway

import (
	"context"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc/metadata"
)

// MuxOptions 是 NewMux 的装配选项。
type MuxOptions struct {
	// ErrorHandler 是旧式错误处理器；ErrorEncoder 优先。
	ErrorHandler runtime.ErrorHandlerFunc
	// ErrorEncoder 是新式错误编码器；nil 时回落到安全默认。
	ErrorEncoder ErrorEncoder

	// IncomingExtra 追加入站放行的项目专属 header（传给 IncomingMatcher）。
	IncomingExtra []string

	// OutgoingDirect 追加出站直透的项目专属 header（传给 OutgoingMatcher）。
	OutgoingDirect []string

	// HeaderPolicy 非 nil 时完全接管入/出站 header 策略。
	HeaderPolicy *HeaderPolicy
	// Marshaler 为空时使用 NewMarshaler()（snake_case）。
	Marshaler runtime.Marshaler

	// ServeMuxOptions 追加 runtime.ServeMux 选项。
	ServeMuxOptions []runtime.ServeMuxOption

	// Metadata 是请求 metadata annotator；server 默认用它注入可信 client-ip。
	Metadata func(context.Context, *http.Request) metadata.MD
}

// NewMux 构造 grpc-gateway ServeMux（平移自 torchwood NewGRPCGatewayServer 的
// mux 装配段）：统一错误处理器 + 入/出站 header matcher + 三个 marshaler 槽位
// （*、*/*、application/json）全部装 NewMarshaler()。
func NewMux(o MuxOptions) *runtime.ServeMux {
	if o.ErrorEncoder != nil {
		o.ErrorHandler = NewEncoderErrorHandler(o.ErrorEncoder)
	}
	if o.ErrorHandler == nil {
		o.ErrorHandler = NewEncoderErrorHandler(DefaultErrorEncoder(ErrorOptions{}))
	}
	incoming := IncomingMatcher(o.IncomingExtra...)
	outgoing := OutgoingMatcher(o.OutgoingDirect...)
	if o.HeaderPolicy != nil {
		policy := *o.HeaderPolicy
		incoming = IncomingPolicy(policy)
		outgoing = OutgoingPolicy(policy)
	}
	marshaler := o.Marshaler
	if marshaler == nil {
		marshaler = NewMarshaler()
	}
	opts := []runtime.ServeMuxOption{
		runtime.WithErrorHandler(o.ErrorHandler),
		runtime.WithIncomingHeaderMatcher(incoming),
		runtime.WithOutgoingHeaderMatcher(outgoing),
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
