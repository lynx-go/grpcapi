// Package gateway 装配 grpc-gateway 反向代理：统一错误处理、protojson 序列化、
// 入/出站 header 策略与同地址拨号。机制平移自 torchwood
// cmd/server/internal/runtime（errors.go / grpc_gateway.go），项目契约
// （错误体 JSON 形状、code→error_code 映射、项目专属 header）经参数注入。
package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
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
	// CodeToHTTP 覆盖内置 grpc code → HTTP 状态码映射（仅声明的条目生效）。
	// 缺省内置表含 Canceled→499（客户端主动断开，非标准但业界惯例）。
	CodeToHTTP map[codes.Code]int
	CodeString func(codes.Code) string
	// Sanitize 返回 true 时把 Internal/Unknown 替换为通用文案
	// （fail-closed：原始消息只进日志、不下发）。
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

// NewEncoderErrorHandler 把 ErrorEncoder 适配为 grpc-gateway 错误处理器
// （runtime.WithErrorHandler 的注入物）。
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
		slog.Default().ErrorContext(r.Context(), "failed to encode error body", "error", merr)
		return
	}
	_, _ = w.Write(append(data, '\n'))
}

// DefaultCodeToHTTP 是内置 grpc code → HTTP 状态码映射表
// （平移自 torchwood grpcCodeToHTTP）。
func DefaultCodeToHTTP(code codes.Code) int {
	switch code {
	case codes.OK:
		return http.StatusOK
	case codes.Canceled:
		return 499
	case codes.Unknown:
		return http.StatusInternalServerError
	case codes.InvalidArgument, codes.FailedPrecondition, codes.OutOfRange:
		return http.StatusBadRequest
	case codes.DeadlineExceeded:
		return http.StatusGatewayTimeout
	case codes.NotFound:
		return http.StatusNotFound
	case codes.AlreadyExists, codes.Aborted:
		return http.StatusConflict
	case codes.PermissionDenied:
		return http.StatusForbidden
	case codes.Unauthenticated:
		return http.StatusUnauthorized
	case codes.ResourceExhausted:
		return http.StatusTooManyRequests
	case codes.Unimplemented:
		return http.StatusNotImplemented
	case codes.Unavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

// NewErrorID 生成错误追踪 ID：crypto/rand 128 位十六进制（32 字符）。
// torchwood 用 uuid.NewString()，此处为避免 uuid 依赖改用等价的随机十六进制；
// 字段只作关联日志用途，格式不对客户端承诺。熵源故障（极罕见）时退化为
// 纳秒时间戳，保证字段仍在。
func NewErrorID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(b[:])
}

// retryAfterSeconds 从 status details 提取 RetryInfo 的建议退避秒数
// （向上取整，至少 1s）；无 detail 或时长非法时返回 false。
// 平移自 torchwood errors_retry_after 语义。
func retryAfterSeconds(st *status.Status) (string, bool) {
	for _, d := range st.Details() {
		if ri, ok := d.(*errdetails.RetryInfo); ok && ri.GetRetryDelay().AsDuration() > 0 {
			secs := int64(math.Ceil(ri.GetRetryDelay().AsDuration().Seconds()))
			if secs < 1 {
				secs = 1
			}
			return strconv.FormatInt(secs, 10), true
		}
	}
	return "", false
}
