package gateway

import (
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
)

func TestNewMarshalerContentAndShape(t *testing.T) {
	m := NewMarshaler()

	if got := m.ContentType(nil); got != "application/json" {
		t.Fatalf("ContentType = %q, want application/json", got)
	}
	// UseProtoNames=true（snake_case 键）+ EmitUnpopulated=false（零值字段不下发）。
	data, err := m.Marshal(&errdetails.ErrorInfo{Domain: "demo"})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(data) != `{"domain":"demo"}` {
		t.Fatalf("Marshal 输出 = %s, want {\"domain\":\"demo\"}", data)
	}
}

func TestNewMarshalerUnmarshalDiscardUnknown(t *testing.T) {
	m := NewMarshaler()
	var out errdetails.ErrorInfo
	if err := m.Unmarshal([]byte(`{"bogus_field":1,"domain":"demo"}`), &out); err != nil {
		t.Fatalf("未知字段应被容错: %v", err)
	}
	if out.GetDomain() != "demo" {
		t.Fatalf("Unmarshal 丢字段: domain=%q", out.GetDomain())
	}
}

func TestNewMarshalerDelimiter(t *testing.T) {
	m := NewMarshaler()
	concrete, ok := m.(*protoJSONMarshaler)
	if !ok {
		t.Fatalf("NewMarshaler 应返回 *protoJSONMarshaler")
	}
	if string(concrete.JSONPb.Delimiter()) != "\n" {
		t.Fatalf("流式分隔符 = %q, want \\n", concrete.JSONPb.Delimiter())
	}
}
