package gateway

import (
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
)

// MuxOptions 是 NewMux 的装配选项。
type MuxOptions struct {
	// ErrorHandler 必填（统一错误处理器，见 NewErrorHandler）。nil 直接 panic：
	// 装配错误应在启动期炸出，而不是等到首个错误请求时静默回落到
	// grpc-gateway 默认错误体、破坏项目的对外错误契约。
	ErrorHandler runtime.ErrorHandlerFunc

	// IncomingExtra 追加入站放行的项目专属 header（传给 IncomingMatcher）。
	IncomingExtra []string

	// OutgoingDirect 追加出站直透的项目专属 header（传给 OutgoingMatcher）。
	OutgoingDirect []string
}

// NewMux 构造 grpc-gateway ServeMux（平移自 torchwood NewGRPCGatewayServer 的
// mux 装配段）：统一错误处理器 + 入/出站 header matcher + 三个 marshaler 槽位
// （*、*/*、application/json）全部装 NewMarshaler()。
func NewMux(o MuxOptions) *runtime.ServeMux {
	if o.ErrorHandler == nil {
		panic("gateway.NewMux: ErrorHandler 必填（nil 会把项目错误契约静默换成 grpc-gateway 默认错误体）")
	}
	return runtime.NewServeMux(
		runtime.WithErrorHandler(o.ErrorHandler),
		runtime.WithIncomingHeaderMatcher(IncomingMatcher(o.IncomingExtra...)),
		runtime.WithOutgoingHeaderMatcher(OutgoingMatcher(o.OutgoingDirect...)),
		runtime.WithMarshalerOption("*", NewMarshaler()),
		runtime.WithMarshalerOption("*/*", NewMarshaler()),
		runtime.WithMarshalerOption("application/json", NewMarshaler()),
	)
}
