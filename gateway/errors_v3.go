package gateway

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// ErrorResponse 是 ErrorEncoder 的输出。
type ErrorResponse struct {
	Status  int
	Body    any
	Headers http.Header
}

// ErrorEncoder 把 gRPC 错误编码为 HTTP 响应；项目可完全替换错误体契约。
type ErrorEncoder interface {
	Encode(ctx context.Context, err error) ErrorResponse
}

// ErrorEncoderFunc 便于用函数实现 ErrorEncoder。
type ErrorEncoderFunc func(context.Context, error) ErrorResponse

// Encode 实现 ErrorEncoder。
func (f ErrorEncoderFunc) Encode(ctx context.Context, err error) ErrorResponse {
	return f(ctx, err)
}

// ErrorOptions 是 DefaultErrorEncoder 的配置。
type ErrorOptions struct {
	CodeToHTTP map[codes.Code]int
	CodeString func(codes.Code) string
	// Sanitize 返回 true 时把 Internal/Unknown 替换为通用文案。
	Sanitize func(codes.Code) bool
	ErrorID  func() string
	Logger   *slog.Logger
	// 零值安全：默认写 Retry-After；显式关闭才设为 true。
	DisableRetryAfter bool
}

func (o ErrorOptions) codeToHTTP(code codes.Code) int {
	if v, ok := o.CodeToHTTP[code]; ok {
		return v
	}
	return DefaultCodeToHTTP(code)
}

func (o ErrorOptions) codeString(code codes.Code) string {
	if o.CodeString != nil {
		return o.CodeString(code)
	}
	return code.String()
}

func (o ErrorOptions) sanitize(code codes.Code) bool {
	if o.Sanitize != nil {
		return o.Sanitize(code)
	}
	return code == codes.Internal || code == codes.Unknown
}

func (o ErrorOptions) logger() *slog.Logger {
	if o.Logger != nil {
		return o.Logger
	}
	return slog.Default()
}

func (o ErrorOptions) errorID() string {
	if o.ErrorID != nil {
		return o.ErrorID()
	}
	return NewErrorID()
}

// DefaultErrorEncoder 返回安全默认错误编码器：
//
//   - code→HTTP：DefaultCodeToHTTP，可覆盖；
//   - Internal/Unknown 脱敏 + error_id；
//   - 429 从 RetryInfo 提取 Retry-After；
//   - body 为普通 map（非 proto），字段：code/message/error_id。
func DefaultErrorEncoder(opts ErrorOptions) ErrorEncoder {
	return ErrorEncoderFunc(func(ctx context.Context, err error) ErrorResponse {
		st, ok := status.FromError(err)
		if !ok || st == nil {
			st = status.New(codes.Internal, "internal server error")
			opts.logger().ErrorContext(ctx, "http error: non-status error", "error", err)
		}
		httpStatus := opts.codeToHTTP(st.Code())
		message := st.Message()
		errorID := opts.errorID()
		if opts.sanitize(st.Code()) {
			opts.logger().ErrorContext(ctx, "http response: sanitized",
				"code", st.Code().String(), "original_message", st.Message(), "error_id", errorID)
			message = "internal server error"
		}
		headers := make(http.Header)
		if httpStatus == http.StatusTooManyRequests && !opts.DisableRetryAfter {
			if retryAfter, ok := retryAfterSeconds(st); ok {
				headers.Set("Retry-After", retryAfter)
			}
		}
		return ErrorResponse{
			Status:  httpStatus,
			Body:    map[string]any{"code": opts.codeString(st.Code()), "message": message, "error_id": errorID},
			Headers: headers,
		}
	})
}

// NewEncoderErrorHandler 把 ErrorEncoder 适配为 grpc-gateway 错误处理器。
func NewEncoderErrorHandler(e ErrorEncoder) runtime.ErrorHandlerFunc {
	if e == nil {
		e = DefaultErrorEncoder(ErrorOptions{})
	}
	return func(ctx context.Context, _ *runtime.ServeMux, marshaler runtime.Marshaler, w http.ResponseWriter, r *http.Request, err error) {
		resp := e.Encode(ctx, err)
		if resp.Status == 0 {
			resp.Status = http.StatusInternalServerError
		}
		for k, vs := range resp.Headers {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		if w.Header().Get("Content-Type") == "" {
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(resp.Status)
		if resp.Body == nil {
			return
		}
		m := marshaler
		if m == nil {
			m = NewMarshaler()
		}
		data, merr := m.Marshal(resp.Body)
		if merr != nil {
			slog.Default().ErrorContext(ctx, "failed to encode error body", "error", merr)
			return
		}
		_, _ = w.Write(append(data, '\n'))
	}
}

// WriteError 是给 authn/authz HTTP 中间件复用的便捷写出函数。
func WriteError(w http.ResponseWriter, r *http.Request, err error, e ErrorEncoder) {
	if e == nil {
		e = DefaultErrorEncoder(ErrorOptions{})
	}
	resp := e.Encode(r.Context(), err)
	if resp.Status == 0 {
		resp.Status = http.StatusInternalServerError
	}
	for k, vs := range resp.Headers {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(resp.Status)
	if resp.Body == nil {
		return
	}
	var data []byte
	var merr error
	switch b := resp.Body.(type) {
	case proto.Message:
		data, merr = NewMarshaler().Marshal(b)
	case json.RawMessage:
		data = b
	case []byte:
		data = b
	default:
		data, merr = json.Marshal(b)
	}
	if merr != nil {
		return
	}
	_, _ = w.Write(append(data, '\n'))
}
