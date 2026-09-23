// Package gateway 装配 grpc-gateway 反向代理：统一错误处理、protojson 序列化、
// 入/出站 header matcher 与同地址拨号。机制平移自 torchwood
// cmd/server/internal/runtime（errors.go / grpc_gateway.go），项目契约
// （错误体 JSON 形状、code→error_code 映射、项目专属 header）经参数注入。
package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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

// ErrorBodyBuilder 由项目实现，承载对客户端的错误契约（库不感知错误体形状）：
//
//   - Build 构造最终写出的错误体（proto.Message，经 marshaler 序列化为 JSON）；
//   - MapErrorCode 声明 gRPC code → 项目 error_code 的映射（无映射返回 nil）。
//     典型用法是项目 Build 内部委托它填充错误体中的业务错误码字段；接口把两者
//     绑定声明，使项目的“code→error_code 映射表”可与错误体形状分开单独断言
//     （如 guard 式的映射完备性测试）。
type ErrorBodyBuilder interface {
	Build(code codes.Code, message, errorID string) proto.Message
	MapErrorCode(code codes.Code) any
}

// HTTPOptions 是统一错误处理器的行为选项，零值即安全默认。
type HTTPOptions struct {
	// CodeToHTTP 覆盖内置 grpc code → HTTP 状态码映射（仅声明的条目生效）。
	// 缺省内置表含 Canceled→499（客户端主动断开，非标准但业界惯例）。
	CodeToHTTP map[codes.Code]int

	// SanitizeInternal 控制 Internal/Unknown 的对外文案脱敏。零值默认视为
	// true（用 getter 归一）：Go bool 无法区分“未设置”与显式 false，按
	// fail-closed 原则一律视为开启——原始错误消息只进日志、不下发。
	// 未来如需支持显式关闭，需把该字段升级为 *bool。
	SanitizeInternal bool

	// Logger 可选：脱敏路径与非状态错误路径用它记录原始错误。nil 时回落
	// slog.Default()。
	Logger *slog.Logger
}

// sanitizeInternal 归一 SanitizeInternal（见字段注释：当前恒为 true）。
func (o HTTPOptions) sanitizeInternal() bool {
	return true
}

// logger 归一日志器：未注入时回落 slog 默认。
func (o HTTPOptions) logger() *slog.Logger {
	if o.Logger != nil {
		return o.Logger
	}
	return slog.Default()
}

// NewErrorHandler 构造 grpc-gateway 统一错误处理器（runtime.WithErrorHandler
// 的注入物）。行为对齐 torchwood HTTPErrorHandler：
//
//   - grpc code → HTTP 状态码：内置表（含 Canceled→499），CodeToHTTP 可覆盖；
//   - Internal/Unknown 脱敏为通用文案 "internal server error"，生成 error_id
//     一并下发，原始消息连同 error_id 记日志（fail-closed，不泄内部细节）；
//   - 429 响应从 status details 提取 errdetails.RetryInfo 作为 Retry-After
//     （整秒向上取整、至少 1s；无 detail 不设头）；
//   - 错误体经 mux 注入的 marshaler（protojson）写 JSON，
//     Content-Type: application/json。
func NewErrorHandler(b ErrorBodyBuilder, o HTTPOptions) runtime.ErrorHandlerFunc {
	return func(ctx context.Context, mux *runtime.ServeMux, marshaler runtime.Marshaler, w http.ResponseWriter, r *http.Request, err error) {
		st, ok := status.FromError(err)
		if !ok || st == nil {
			// 非状态错误（含 handler 被直接喂 nil 的异常形态）一律归 Internal。
			// err 原样入日志（slog 对 nil 安全），不在这里解引用。
			st = status.New(codes.Internal, "internal server error")
			o.logger().ErrorContext(ctx, "http error: non-status error converted to internal",
				"error", err, "code", st.Code().String())
		}

		httpStatus := o.codeToHTTP(st.Code())

		message := st.Message()
		errorID := NewErrorID()
		if o.sanitizeInternal() && (st.Code() == codes.Internal || st.Code() == codes.Unknown) {
			o.logger().ErrorContext(ctx, "http response: internal error sanitized",
				"code", st.Code().String(), "original_message", st.Message(),
				"error_id", errorID, "path", r.URL.Path)
			message = "internal server error"
		}

		// 429 携带 Retry-After：从 status 的 RetryInfo detail 提取建议退避
		// （整秒向上取整）；无 detail 时不设头，由客户端自行退避。
		if httpStatus == http.StatusTooManyRequests {
			if retryAfter, ok := retryAfterSeconds(st); ok {
				w.Header().Set("Retry-After", retryAfter)
			}
		}

		resp := b.Build(st.Code(), message, errorID)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(httpStatus)
		m := marshaler
		if m == nil {
			m = NewMarshaler()
		}
		data, merr := m.Marshal(resp)
		if merr != nil {
			o.logger().ErrorContext(ctx, "failed to encode error response",
				"error", merr, "error_id", errorID)
			return
		}
		if _, werr := w.Write(append(data, '\n')); werr != nil {
			o.logger().ErrorContext(ctx, "failed to write error response",
				"error", werr, "error_id", errorID)
		}
	}
}

// codeToHTTP 按自定义映射优先、内置表兜底解析 HTTP 状态码。
func (o HTTPOptions) codeToHTTP(code codes.Code) int {
	if v, ok := o.CodeToHTTP[code]; ok {
		return v
	}
	return DefaultCodeToHTTP(code)
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
