package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

// fakeBuilder 用 errdetails.ErrorInfo 充当错误体（库测试不引入项目错误契约），
// 把 Build 收到的 (code, message, errorID) 全部投影进字段供断言。
type fakeBuilder struct {
	mapped map[codes.Code]any

	lastCode    codes.Code
	lastMessage string
	lastErrorID string
	buildCalls  int
}

func (b *fakeBuilder) Build(code codes.Code, message, errorID string) proto.Message {
	b.buildCalls++
	b.lastCode, b.lastMessage, b.lastErrorID = code, message, errorID
	ec := ""
	if s, ok := b.MapErrorCode(code).(string); ok {
		ec = s
	}
	return &errdetails.ErrorInfo{
		Reason:   code.String(),
		Domain:   message,
		Metadata: map[string]string{"error_id": errorID, "error_code": ec},
	}
}

func (b *fakeBuilder) MapErrorCode(code codes.Code) any {
	if v, ok := b.mapped[code]; ok {
		return v
	}
	return nil
}

// compile-time：接口形状与库默认序列化器实现必须成立。
var (
	_ ErrorBodyBuilder  = (*fakeBuilder)(nil)
	_ runtime.Marshaler = NewMarshaler()
)

func errorHandlerForTest(b *fakeBuilder, o HTTPOptions) runtime.ErrorHandlerFunc {
	if b == nil {
		b = &fakeBuilder{}
	}
	return NewErrorHandler(b, o)
}

// doErrorRequest 经 httptest 直接驱动错误处理器（mux 传 nil、marshaler 传 nil，
// 覆盖 handler 内置回退路径）。
func doErrorRequest(t *testing.T, h runtime.ErrorHandlerFunc, err error) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/things", nil)
	h(context.Background(), nil, nil, rec, req, err)
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
	h := errorHandlerForTest(nil, HTTPOptions{})
	for _, tc := range cases {
		rec := doErrorRequest(t, h, status.New(tc.code, "boom").Err())
		if rec.Code != tc.want {
			t.Errorf("code %s → HTTP %d, want %d", tc.code, rec.Code, tc.want)
		}
	}
	// OK 档只存在于内置表（错误处理器收到 nil error 时按安全语义归 Internal）。
	if got := DefaultCodeToHTTP(codes.OK); got != 200 {
		t.Errorf("DefaultCodeToHTTP(OK) = %d, want 200", got)
	}
}

func TestErrorHandlerCustomCodeToHTTPOverride(t *testing.T) {
	h := errorHandlerForTest(nil, HTTPOptions{
		CodeToHTTP: map[codes.Code]int{codes.NotFound: 410},
	})
	rec := doErrorRequest(t, h, status.New(codes.NotFound, "gone").Err())
	if rec.Code != 410 {
		t.Fatalf("自定义映射未生效：HTTP %d, want 410", rec.Code)
	}
	// 未声明条目回落内置表。
	rec = doErrorRequest(t, h, status.New(codes.Unauthenticated, "no").Err())
	if rec.Code != 401 {
		t.Fatalf("未覆盖条目应回落内置表：HTTP %d, want 401", rec.Code)
	}
}

func TestErrorHandlerSanitizesInternalAndUnknown(t *testing.T) {
	secret := "db password=hunter2"
	h := errorHandlerForTest(nil, HTTPOptions{})
	for _, code := range []codes.Code{codes.Internal, codes.Unknown} {
		b := &fakeBuilder{}
		h := NewErrorHandler(b, HTTPOptions{})
		rec := doErrorRequest(t, h, status.New(code, secret).Err())

		if rec.Code != 500 {
			t.Fatalf("%s → HTTP %d, want 500", code, rec.Code)
		}
		if bytes.Contains(rec.Body.Bytes(), []byte("hunter2")) {
			t.Fatalf("%s 响应体泄漏原始消息: %s", code, rec.Body.String())
		}
		if b.lastMessage != "internal server error" {
			t.Fatalf("%s 传给 Build 的消息应为脱敏文案，得到 %q", code, b.lastMessage)
		}
		if b.lastCode != code {
			t.Fatalf("Build 收到 code %s, want %s", b.lastCode, code)
		}
	}
	// 非 Internal/Unknown 不脱敏。
	rec := doErrorRequest(t, h, status.New(codes.NotFound, secret).Err())
	if !bytes.Contains(rec.Body.Bytes(), []byte("hunter2")) {
		t.Fatalf("NotFound 应原样下发消息: %s", rec.Body.String())
	}
}

func TestErrorHandlerLogsOriginalMessageOnSanitize(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	h := errorHandlerForTest(nil, HTTPOptions{Logger: logger})
	doErrorRequest(t, h, status.New(codes.Internal, "the-secret").Err())

	logged := buf.String()
	if !bytes.Contains([]byte(logged), []byte("the-secret")) {
		t.Fatalf("脱敏日志缺少原始消息: %s", logged)
	}
	if !bytes.Contains([]byte(logged), []byte("error_id")) {
		t.Fatalf("脱敏日志缺少 error_id: %s", logged)
	}
}

func TestErrorHandlerEmitsErrorID(t *testing.T) {
	b := &fakeBuilder{}
	h := NewErrorHandler(b, HTTPOptions{})
	rec := doErrorRequest(t, h, status.New(codes.NotFound, "x").Err())

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应体不是 JSON: %v\n%s", err, rec.Body.String())
	}
	meta, _ := body["metadata"].(map[string]any)
	id, _ := meta["error_id"].(string)
	if id == "" {
		t.Fatalf("响应体缺少 error_id: %s", rec.Body.String())
	}
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(id) {
		t.Fatalf("error_id 形态异常（期望 32 位十六进制）: %q", id)
	}
	// 两次请求 error_id 不重复。
	rec2 := doErrorRequest(t, h, status.New(codes.NotFound, "x").Err())
	var body2 map[string]any
	if err := json.Unmarshal(rec2.Body.Bytes(), &body2); err != nil {
		t.Fatal(err)
	}
	meta2, _ := body2["metadata"].(map[string]any)
	if meta2["error_id"] == id {
		t.Fatalf("error_id 重复: %s", id)
	}
	if b.buildCalls != 2 {
		t.Fatalf("Build 调用次数 = %d, want 2", b.buildCalls)
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
	for _, tc := range cases {
		h := errorHandlerForTest(nil, HTTPOptions{})
		rec := doErrorRequest(t, h, tc.err)
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
	b := &fakeBuilder{}
	h := NewErrorHandler(b, HTTPOptions{})
	rec := doErrorRequest(t, h, errors.New("plain boom"))
	if rec.Code != 500 {
		t.Fatalf("非状态错误应归 Internal：HTTP %d", rec.Code)
	}
	if b.lastCode != codes.Internal || b.lastMessage != "internal server error" {
		t.Fatalf("非状态错误应走脱敏路径: code=%s message=%q", b.lastCode, b.lastMessage)
	}
}

func TestErrorHandlerBodyShape(t *testing.T) {
	b := &fakeBuilder{mapped: map[codes.Code]any{codes.NotFound: "NOT_FOUND"}}
	h := NewErrorHandler(b, HTTPOptions{})
	rec := doErrorRequest(t, h, status.New(codes.NotFound, "no such thing").Err())

	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应体不是 JSON: %v", err)
	}
	if body["reason"] != "NotFound" || body["domain"] != "no such thing" {
		t.Fatalf("响应体字段不符: %s", rec.Body.String())
	}
	meta, _ := body["metadata"].(map[string]any)
	if meta["error_code"] != "NOT_FOUND" {
		t.Fatalf("MapErrorCode 结果未进入错误体: %s", rec.Body.String())
	}
	if _, ok := meta["error_id"].(string); !ok {
		t.Fatalf("缺 error_id: %s", rec.Body.String())
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
