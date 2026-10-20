package gateway

import (
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
)

// HandlerOptions 把 gateway mux 与普通 HTTP 路由/中间件组合成 handler。
type HandlerOptions struct {
	Gateway     *runtime.ServeMux
	Middleware  []func(http.Handler) http.Handler
	ExtraRoutes func(*http.ServeMux)
}

// NewHandler 返回可直接挂到 http.Server 的 handler。
func NewHandler(o HandlerOptions) http.Handler {
	root := http.NewServeMux()
	if o.Gateway != nil {
		root.Handle("/", o.Gateway)
	}
	if o.ExtraRoutes != nil {
		o.ExtraRoutes(root)
	}
	var h http.Handler = root
	for i := len(o.Middleware) - 1; i >= 0; i-- {
		h = o.Middleware[i](h)
	}
	return h
}
