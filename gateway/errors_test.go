package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// doErrorRequest 经 httptest 直接驱动 NewEncoderErrorHandler（mux 传 nil、
// marshaler 传 nil，覆盖 handler 内置回退路径）。
func doErrorRequest(t *testing.T, e ErrorEncoder, err error) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/things", nil)
	NewEncoderErrorHandler(e)(context.Background(), nil, nil, rec, req, err)
	return rec
}

func TestErrorHandlerMapsCodeToHTTP(t *testing.T) {
	cases := []struct {
		code codes.Code
		want int
	}{
		{codes.Canceled, 499}, // 客户端主动断开的非标映射
		{codes.Unknown, 500},
		{codes.InvalidArgument, 400},
		{codes.FailedPrecondition, 400},
		{codes.OutOfRange, 400},
		{codes.DeadlineExceeded, 504},
		{codes.NotFound, 404},
		{codes.AlreadyExists, 409},
		{codes.Aborted, 409},
		{codes.PermissionDenied, 403},
		{codes.Unauthenticated, 401},
		{codes.ResourceExhausted, 429},
		{codes.Unimplemented, 501},
		{codes.Unavailable, 503},
		{codes.DataLoss, 500},
		{codes.Internal, 500},
	}
	enc := DefaultErrorEncoder(ErrorOptions{Logger: discardLogger()})
	for _, tc := range cases {
		rec := doErrorRequest(t, enc, status.New(tc.code, "boom").Err())
		if rec.Code != tc.want {
			t.Errorf("code %s → HTTP %d, want %d", tc.code, rec.Code, tc.want)
		}
	}
	// OK 档只存在于内置表。
	if got := DefaultCodeToHTTP(codes.OK); got != 200 {
		t.Errorf("DefaultCodeToHTTP(OK) = %d, want 200", got)
	}
}

func TestErrorHandlerCustomCodeToHTTPOverride(t *testing.T) {
	enc := DefaultErrorEncoder(ErrorOptions{
		Logger:     discardLogger(),
		CodeToHTTP: map[codes.Code]int{codes.NotFound: 410},
	})
	rec := doErrorRequest(t, enc, status.New(codes.NotFound, "gone").Err())
	if rec.Code != 410 {
		t.Fatalf("自定义映射未生效：HTTP %d, want 410", rec.Code)
	}
	// 未声明条目回落内置表。
	rec = doErrorRequest(t, enc, status.New(codes.Unauthenticated, "no").Err())
	if rec.Code != 401 {
		t.Fatalf("未覆盖条目应回落内置表：HTTP %d, want 401", rec.Code)
	}
}

func TestErrorHandlerSanitizesInternalAndUnknown(t *testing.T) {
	secret := "db password=hunter2"
	enc := DefaultErrorEncoder(ErrorOptions{Logger: discardLogger()})
	for _, code := range []codes.Code{codes.Internal, codes.Unknown} {
		rec := doErrorRequest(t, enc, status.New(code, secret).Err())
		if rec.Code != 500 {
			t.Fatalf("%s → HTTP %d, want 500", code, rec.Code)
		}
		if bytes.Contains(rec.Body.Bytes(), []byte("hunter2")) {
			t.Fatalf("%s 响应体泄漏原始消息: %s", code, rec.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body["message"] != "internal server error" {
			t.Fatalf("%s 错误体消息应为脱敏文案: %s", code, rec.Body.String())
		}
	}
	// 非 Internal/Unknown 不脱敏。
	rec := doErrorRequest(t, enc, status.New(codes.NotFound, secret).Err())
	if !bytes.Contains(rec.Body.Bytes(), []byte("hunter2")) {
		t.Fatalf("NotFound 应原样下发消息: %s", rec.Body.String())
	}
}

func TestErrorHandlerLogsOriginalMessageOnSanitize(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	enc := DefaultErrorEncoder(ErrorOptions{Logger: logger})
	doErrorRequest(t, enc, status.New(codes.Internal, "the-secret").Err())

	logged := buf.String()
	if !bytes.Contains([]byte(logged), []byte("the-secret")) {
		t.Fatalf("脱敏日志缺少原始消息: %s", logged)
	}
	if !bytes.Contains([]byte(logged), []byte("error_id")) {
		t.Fatalf("脱敏日志缺少 error_id: %s", logged)
	}
}

func TestErrorHandlerEmitsErrorID(t *testing.T) {
	enc := DefaultErrorEncoder(ErrorOptions{Logger: discardLogger()})
	rec := doErrorRequest(t, enc, status.New(codes.NotFound, "x").Err())

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应体不是 JSON: %v\n%s", err, rec.Body.String())
	}
	id, _ := body["error_id"].(string)
	if id == "" {
		t.Fatalf("响应体缺少 error_id: %s", rec.Body.String())
	}
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(id) {
		t.Fatalf("error_id 形态异常（期望 32 位十六进制）: %q", id)
	}
	// 两次请求 error_id 不重复。
	rec2 := doErrorRequest(t, enc, status.New(codes.NotFound, "x").Err())
	var body2 map[string]any
	if err := json.Unmarshal(rec2.Body.Bytes(), &body2); err != nil {
		t.Fatal(err)
	}
	if body2["error_id"] == id {
		t.Fatalf("error_id 重复: %s", id)
	}
}

func TestErrorHandlerRetryAfter(t *testing.T) {
	retryStatus := func(d time.Duration) error {
		st, err := status.New(codes.ResourceExhausted, "qps").
			WithDetails(&errdetails.RetryInfo{RetryDelay: durationpb.New(d)})
		if err != nil {
			t.Fatalf("WithDetails: %v", err)
		}
		return st.Err()
	}
	cases := []struct {
		name     string
		err      error
		wantHas  bool
		wantHead string
	}{
		{
			name:     "1.5s 向上取整为 2",
			err:      retryStatus(1500 * time.Millisecond),
			wantHas:  true,
			wantHead: "2",
		},
		{
			name:     "100ms 至少 1s",
			err:      retryStatus(100 * time.Millisecond),
			wantHas:  true,
			wantHead: "1",
		},
		{
			name:    "无 detail 不设头",
			err:     status.New(codes.ResourceExhausted, "qps").Err(),
			wantHas: false,
		},
		{
			name: "非 429 不设头",
			err: func() error {
				st, err := status.New(codes.NotFound, "x").
					WithDetails(&errdetails.RetryInfo{RetryDelay: durationpb.New(5 * time.Second)})
				if err != nil {
					t.Fatalf("WithDetails: %v", err)
				}
				return st.Err()
			}(),
			wantHas: false,
		},
		{
			name:    "零时长 detail 不设头",
			err:     retryStatus(0),
			wantHas: false,
		},
	}
	enc := DefaultErrorEncoder(ErrorOptions{Logger: discardLogger()})
	for _, tc := range cases {
		rec := doErrorRequest(t, enc, tc.err)
		got := rec.Header().Get("Retry-After")
		if tc.wantHas && got != tc.wantHead {
			t.Errorf("%s: Retry-After = %q, want %q", tc.name, got, tc.wantHead)
		}
		if !tc.wantHas && got != "" {
			t.Errorf("%s: 不应设置 Retry-After，得到 %q", tc.name, got)
		}
	}
}

func TestErrorHandlerNonStatusError(t *testing.T) {
	enc := DefaultErrorEncoder(ErrorOptions{Logger: discardLogger()})
	rec := doErrorRequest(t, enc, errors.New("plain boom"))
	if rec.Code != 500 {
		t.Fatalf("非状态错误应归 Internal：HTTP %d", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["message"] != "internal server error" {
		t.Fatalf("非状态错误应走脱敏路径: %s", rec.Body.String())
	}
}

func TestNewEncoderErrorHandlerNilEncoder(t *testing.T) {
	// nil encoder 回落安全默认，未注册路由形态的错误仍可写出。
	rec := doErrorRequest(t, nil, status.New(codes.NotFound, "x").Err())
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
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

func TestNewErrorID(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id := NewErrorID()
		if len(id) != 32 {
			t.Fatalf("error_id 长度 = %d, want 32", len(id))
		}
		if seen[id] {
			t.Fatalf("error_id 重复: %s", id)
		}
		seen[id] = true
	}
}
