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
// "application/json; charset=utf-8"，torchwood 错误处理器显式设置
// Content-Type 时用的是无参数形态，保持一致。
func (m *protoJSONMarshaler) ContentType(_ interface{}) string {
	return "application/json"
}

// NewMarshaler 返回 grpc-gateway 的统一 protojson 序列化器：
//
//   - Marshal：UseProtoNames=true（字段名 snake_case）+ EmitUnpopulated=false
//     （零值字段不下发）；
//   - Unmarshal：DiscardUnknown=true（未知字段容错，向前兼容）；
//   - 流式分隔符保持 JSONPb 默认 "\n"。
func NewMarshaler() runtime.Marshaler {
	return &protoJSONMarshaler{
		JSONPb: &runtime.JSONPb{
			MarshalOptions: protojson.MarshalOptions{
				UseProtoNames:   true,
				EmitUnpopulated: false,
			},
			UnmarshalOptions: protojson.UnmarshalOptions{DiscardUnknown: true},
		},
	}
}
