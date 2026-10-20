package gateway

import (
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/protobuf/encoding/protojson"
)

// MarshalerOptions 是 protojson 序列化选项。
type MarshalerOptions struct {
	// UseJSONNames 默认 false = UseProtoNames (snake_case)。
	UseJSONNames    bool
	EmitUnpopulated bool
	// RejectUnknownFields 默认 false = discard unknown（向前兼容）。
	RejectUnknownFields bool
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
