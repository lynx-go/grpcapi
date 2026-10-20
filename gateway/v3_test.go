package gateway

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestDefaultErrorEncoder(t *testing.T) {
	enc := DefaultErrorEncoder(ErrorOptions{
		ErrorID: func() string { return "err-1" },
		Logger:  discardLogger(),
	})
	resp := enc.Encode(context.Background(), status.Error(codes.InvalidArgument, "bad input"))
	if resp.Status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.Status)
	}
	body, ok := resp.Body.(map[string]any)
	if !ok || body["code"] != "InvalidArgument" || body["message"] != "bad input" || body["error_id"] != "err-1" {
		t.Fatalf("body = %#v", resp.Body)
	}

	resp = enc.Encode(context.Background(), status.Error(codes.Internal, "db password leaked"))
	body = resp.Body.(map[string]any)
	if resp.Status != http.StatusInternalServerError || body["message"] != "internal server error" {
		t.Fatalf("internal not sanitized: %#v", resp)
	}
}

func TestDefaultErrorEncoderRetryAfter(t *testing.T) {
	st, err := status.New(codes.ResourceExhausted, "slow down").WithDetails(&errdetails.RetryInfo{
		RetryDelay: durationpb.New(1500 * time.Millisecond),
	})
	if err != nil {
		t.Fatal(err)
	}
	resp := DefaultErrorEncoder(ErrorOptions{Logger: discardLogger()}).Encode(context.Background(), st.Err())
	if resp.Status != http.StatusTooManyRequests {
		t.Fatalf("status = %d", resp.Status)
	}
	if got := resp.Headers.Get("Retry-After"); got != "2" {
		t.Fatalf("Retry-After = %q, want 2", got)
	}
}

func TestWriteError(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteError(rec, httptest.NewRequest(http.MethodGet, "/x", nil), status.Error(codes.NotFound, "missing"),
		DefaultErrorEncoder(ErrorOptions{Logger: discardLogger(), ErrorID: func() string { return "e" }}))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"error_id":"e"`) {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestHeaderPolicy(t *testing.T) {
	in := IncomingPolicy(DefaultHeaderPolicy())
	if _, ok := in("authorization"); ok {
		t.Fatal("authorization must be denied")
	}
	if _, ok := in("x-grpcapi-client-ip"); ok {
		t.Fatal("internal client-ip must be denied")
	}
	if got, ok := in("Cookie"); !ok || got != "cookie" {
		t.Fatalf("cookie = %q, %v", got, ok)
	}
	out := OutgoingPolicy(DefaultHeaderPolicy())
	if got, ok := out("set-cookie"); !ok || got != "Set-Cookie" {
		t.Fatalf("set-cookie = %q, %v", got, ok)
	}
	if got, ok := out("x-request-id"); !ok || got != "Grpc-Metadata-x-request-id" {
		t.Fatalf("fallback = %q, %v", got, ok)
	}

	// 显式空 Allow + 空 fallback 表示不放行任何头。
	emptyAllow := HeaderPolicy{Allow: []string{}, FallbackIn: func(string) (string, bool) { return "", false }}
	if _, ok := IncomingPolicy(emptyAllow)("cookie"); ok {
		t.Fatal("empty Allow with empty fallback should not allow cookie")
	}
}

func TestMarshalerOptions(t *testing.T) {
	msg := &errdetails.BadRequest{FieldViolations: []*errdetails.BadRequest_FieldViolation{{Field: "x"}}}
	snake, err := NewMarshaler().Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(snake), `"field_violations"`) {
		t.Fatalf("snake marshaler = %s", snake)
	}
	camel, err := CamelCaseMarshaler().Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(camel), `"fieldViolations"`) {
		t.Fatalf("camel marshaler = %s", camel)
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
