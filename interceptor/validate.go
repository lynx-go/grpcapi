package interceptor

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"buf.build/go/protovalidate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// ValidateInterceptor 按 proto 上的 buf.validate 注解（protovalidate，
// CEL 运行时求值）对请求消息做形状校验：required/长度/正则/枚举/范围
// 一类约束在 proto 声明、在此统一生效；跨字段与业务规则仍留在 app 用例
// 层（两层语义边界由项目文档约定）。
//
// 链上位于链尾（chain.SlotValidate，audit/usage 之后、handler 之前）：
// 校验失败的请求与手写校验时期行为完全一致——产生 InvalidArgument 审计
// 行并计入用量，本拦截器只是把 handler 开头的形状检查外提为 proto 声明。
// 仅 unary，与整条拦截器链一致。
type ValidateInterceptor struct {
	validator protovalidate.Validator
	// initErr 是 validator 构造失败的兜底记录（CEL 环境配置级故障）。
	// 构造器签名无 error，失败在首个被校验请求上以 Internal 暴露
	// （fail-closed，不放行未校验请求）。
	initErr error
	// logger 记录初始化/求值故障细节；nil 时回落 slog.Default()。
	// Internal 的 message 会原样到达直接 gRPC 客户端，细节只进日志。
	logger *slog.Logger
}

// NewValidate 构造校验拦截器。
func NewValidate() *ValidateInterceptor {
	v := &ValidateInterceptor{}
	validator, err := protovalidate.New()
	if err != nil {
		v.initErr = err
		return v
	}
	v.validator = validator
	return v
}

// Unary 返回链尾拦截器（对应 StageValidate）。
func (v *ValidateInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if v == nil || FrameworkExempt(info.FullMethod) {
			return handler(ctx, req)
		}
		if err := v.validateMessage(req); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// Stream 返回 stream 校验拦截器：包装 RecvMsg，逐条校验 client/bidi 消息；
// server-streaming 的首个请求也会被校验。
func (v *ValidateInterceptor) Stream() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if v == nil || FrameworkExempt(info.FullMethod) {
			return handler(srv, ss)
		}
		if v.validator == nil {
			return v.initError()
		}
		return handler(srv, &validatingStream{ServerStream: ss, validator: v})
	}
}

func (v *ValidateInterceptor) validateMessage(m any) error {
	if v == nil || v.validator == nil {
		return v.initError()
	}
	msg, ok := m.(proto.Message)
	if !ok {
		// 非 proto 消息（理论不可达）不校验，交由后续链路处理。
		return nil
	}
	if err := v.validator.Validate(msg); err != nil {
		return v.validateStatusError(err)
	}
	return nil
}

func (v *ValidateInterceptor) errorLogger() *slog.Logger {
	if v != nil && v.logger != nil {
		return v.logger
	}
	return slog.Default()
}

func (v *ValidateInterceptor) initError() error {
	// 客户端只收通用文案；initErr 细节（CEL 环境配置）进日志。
	const msg = "request validation rules failed to initialize"
	var detail error
	if v != nil {
		detail = v.initErr
	}
	v.errorLogger().Error(msg, "error", detail)
	return status.Error(codes.Internal, msg)
}

// validateStatusError 映射校验错误：规则违规 → InvalidArgument（多条以
// "; " 连接为单行，经 gateway 错误处理器原样进入 error.message）；CEL
// 编译/求值故障 → Internal（注解缺陷属服务端 bug，fail-closed 拒绝而非
// 放行未校验请求），原始错误只进日志不下发。
func (v *ValidateInterceptor) validateStatusError(err error) error {
	var violations *protovalidate.ValidationError
	if errors.As(err, &violations) {
		return status.Error(codes.InvalidArgument, formatViolations(violations.Violations))
	}
	const msg = "request validation rules failed to evaluate"
	v.errorLogger().Error(msg, "error", err)
	return status.Error(codes.Internal, msg)
}

func formatViolations(violations []*protovalidate.Violation) string {
	parts := make([]string, 0, len(violations))
	for _, violation := range violations {
		parts = append(parts, violation.String())
	}
	return strings.Join(parts, "; ")
}
