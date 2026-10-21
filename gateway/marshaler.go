package gateway

import (
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/protobuf/encoding/protojson"
)

// protoJSONMarshaler 覆盖 ContentType 的 protojson 序列化器
// （平移自 torchwood CustomMarshaler）。
type protoJSONMarshaler struct {
	*runtime.JSONPb
}

// ContentType 恒返回 application/json：JSONPb 默认返回
// "application/json; charset=utf-8"，错误处理器显式设置 Content-Type 时
// 用的是无参数形态，保持一致。
func (m *protoJSONMarshaler) ContentType(_ interface{}) string {
	return "application/json"
}

// MarshalerOptions 是 protojson 序列化选项。
type MarshalerOptions struct {
	// UseJSONNames 默认 false = UseProtoNames (snake_case)。
	UseJSONNames    bool
	EmitUnpopulated bool
	// RejectUnknownFields 默认 false = discard unknown（向前兼容）。
	RejectUnknownFields bool
}

// NewMarshaler 返回默认 protojson 序列化器：snake_case、零值字段不下发、
// 未知字段容错（向前兼容）。需要 camelCase 用 CamelCaseMarshaler()，
// 需要严格未知字段用 NewMarshalerWithOptions。
func NewMarshaler() runtime.Marshaler {
	return NewMarshalerWithOptions(MarshalerOptions{})
}

// NewMarshalerWithOptions 构造 protojson marshaler。
func NewMarshalerWithOptions(o MarshalerOptions) runtime.Marshaler {
	return &protoJSONMarshaler{
		JSONPb: &runtime.JSONPb{
			MarshalOptions: protojson.MarshalOptions{
				UseProtoNames:   !o.UseJSONNames,
				EmitUnpopulated: o.EmitUnpopulated,
			},
			UnmarshalOptions: protojson.UnmarshalOptions{
				DiscardUnknown: !o.RejectUnknownFields,
			},
		},
	}
}

// CamelCaseMarshaler 返回 protojson 标准 camelCase 序列化器。
func CamelCaseMarshaler() runtime.Marshaler {
	return NewMarshalerWithOptions(MarshalerOptions{UseJSONNames: true})
}
