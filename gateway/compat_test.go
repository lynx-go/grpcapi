package gateway_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lynx-go/grpcapi/gateway"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// legacyBuilder 复刻 torchwood 形态的错误体契约：Build 返回真实 proto
// message（经 protojson 序列化），映射表单独暴露供守卫断言。
type legacyBuilder struct{}

func (legacyBuilder) Build(code codes.Code, message, errorID string) proto.Message {
	return &errdetails.ErrorInfo{
		Reason: code.String(),
		Domain: "torchwood.test",
		Metadata: map[string]string{
			"message":    message,
			"error_id":   errorID,
			"error_code": "E_INTERNAL",
		},
	}
}

func (legacyBuilder) MapErrorCode(code codes.Code) any { return "E_INTERNAL" }

func TestCompatBuilderEncoder(t *testing.T) {
	enc := gateway.BuilderEncoder(legacyBuilder{}, gateway.HTTPOptions{})
	resp := enc.Encode(context.Background(), status.Error(codes.NotFound, "note not found"))
	if resp.Status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.Status)
	}
	body, ok := resp.Body.(*errdetails.ErrorInfo)
	if !ok {
		t.Fatalf("body type = %T, want *errdetails.ErrorInfo", resp.Body)
	}
	if body.Metadata["message"] != "note not found" || body.Metadata["error_id"] == "" || body.Metadata["error_code"] != "E_INTERNAL" {
		t.Fatalf("body = %+v", body.Metadata)
	}
}

func TestCompatBuilderEncoderSanitizesInternal(t *testing.T) {
	enc := gateway.BuilderEncoder(legacyBuilder{}, gateway.HTTPOptions{})
	resp := enc.Encode(context.Background(), status.Error(codes.Internal, "db password leaked"))
	body := resp.Body.(*errdetails.ErrorInfo)
	if body.Metadata["message"] != "internal server error" {
		t.Fatalf("message = %q, want sanitized", body.Metadata["message"])
	}
	if body.Metadata["error_id"] == "" {
		t.Fatal("error_id missing")
	}
}

func TestCompatNewErrorHandlerWritesBuilderBody(t *testing.T) {
	handler := gateway.NewErrorHandler(legacyBuilder{}, gateway.HTTPOptions{})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/v1/notes", nil)
	handler(r.Context(), nil, gateway.NewMarshaler(), w, r, status.Error(codes.Unauthenticated, "bad token"))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q", ct)
	}
	if body := w.Body.String(); !strings.Contains(body, "E_INTERNAL") || !strings.Contains(body, "bad token") {
		t.Fatalf("body = %s", body)
	}
}

func TestCompatIncomingMatcher(t *testing.T) {
	m := gateway.IncomingMatcher("X-Torchwood-Project")
	if _, ok := m("Authorization"); ok {
		t.Fatal("authorization must be denied")
	}
	if _, ok := m("x-grpcapi-client-ip"); ok {
		t.Fatal("x-grpcapi-client-ip must be denied")
	}
	if k, ok := m("X-Torchwood-Project"); !ok || k != "x-torchwood-project" {
		t.Fatalf("extra allow = %q %v", k, ok)
	}
	if k, ok := m("X-Api-Key"); !ok || k != "x-api-key" {
		t.Fatalf("default allow = %q %v", k, ok)
	}
	if _, ok := m("X-Evil"); ok {
		t.Fatal("unknown custom header must fall back to gateway default (rejected)")
	}
}

func TestCompatOutgoingMatcher(t *testing.T) {
	m := gateway.OutgoingMatcher("X-Torchwood-Replayed")
	if k, ok := m("Set-Cookie"); !ok || k != "Set-Cookie" {
		t.Fatalf("set-cookie = %q %v", k, ok)
	}
	if k, ok := m("X-Torchwood-Replayed"); !ok || k != "X-Torchwood-Replayed" {
		t.Fatalf("direct = %q %v", k, ok)
	}
	if k, ok := m("X-Custom"); !ok || k != "Grpc-Metadata-X-Custom" {
		t.Fatalf("fallback = %q %v", k, ok)
	}
}
