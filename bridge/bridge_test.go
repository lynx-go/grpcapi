package bridge_test

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/lynx-go/grpcapi/bridge"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func readUntil(r *bufio.Reader, needle string, deadline time.Duration) (string, error) {
	var sb strings.Builder
	timer := time.After(deadline)
	for {
		select {
		case <-timer:
			return sb.String(), context.DeadlineExceeded
		default:
		}
		line, err := r.ReadString('\n')
		sb.WriteString(line)
		if strings.Contains(sb.String(), needle) {
			return sb.String(), nil
		}
		if err != nil {
			return sb.String(), err
		}
	}
}

func TestSSEHandlerEvents(t *testing.T) {
	h := bridge.SSEHandler(func(w *bridge.SSEWriter, r *http.Request) error {
		if err := w.Event("note", []byte("line1\nline2")); err != nil {
			return err
		}
		return w.EventWithID("42", "done", []byte(`{"ok":true}`))
	}, bridge.SSEOptions{RetryHint: 3000})
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content-type = %q", ct)
	}
	if resp.Header.Get("X-Accel-Buffering") != "no" {
		t.Fatal("X-Accel-Buffering missing")
	}
	reader := bufio.NewReader(resp.Body)
	head, err := readUntil(reader, "retry: 3000", 2*time.Second)
	if err != nil {
		t.Fatalf("retry hint missing: %v (%q)", err, head)
	}
	block, err := readUntil(reader, `{"ok":true}`, 2*time.Second)
	if err != nil {
		t.Fatalf("events missing: %v (%q)", err, block)
	}
	for _, want := range []string{
		"event: note\n", "data: line1\n", "data: line2\n",
		"id: 42\n", "event: done\n",
	} {
		if !strings.Contains(block, want) {
			t.Fatalf("frame %q missing in %q", want, block)
		}
	}
}

func TestSSEHandlerKeepAlive(t *testing.T) {
	h := bridge.SSEHandler(func(w *bridge.SSEWriter, r *http.Request) error {
		<-r.Context().Done()
		return nil
	}, bridge.SSEOptions{KeepAlive: 30 * time.Millisecond})
	srv := httptest.NewServer(h)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	reader := bufio.NewReader(resp.Body)
	got, err := readUntil(reader, ": keep-alive", 2*time.Second)
	if err != nil {
		t.Fatalf("keep-alive missing: %v (%q)", err, got)
	}
}

func TestSSEHandlerErrorEventSanitized(t *testing.T) {
	h := bridge.SSEHandler(func(w *bridge.SSEWriter, r *http.Request) error {
		return status.Error(codes.Internal, "db exploded")
	}, bridge.SSEOptions{})
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	reader := bufio.NewReader(resp.Body)
	got, err := readUntil(reader, "event: error", 2*time.Second)
	if err != nil {
		t.Fatalf("error event missing: %v (%q)", err, got)
	}
	if strings.Contains(got, "db exploded") {
		t.Fatalf("internal error leaked: %q", got)
	}
}

// fakeUploadStream 收集分帧并在 Finalize 回放统计。
type fakeUploadStream struct {
	chunks [][]byte
}

func (f *fakeUploadStream) Send(_ context.Context, chunk []byte) error {
	f.chunks = append(f.chunks, append([]byte(nil), chunk...))
	return nil
}

func (f *fakeUploadStream) Finalize(context.Context) (any, error) {
	n := 0
	for _, c := range f.chunks {
		n += len(c)
	}
	return map[string]any{"frames": len(f.chunks), "bytes": n}, nil
}

func TestUploadChunksBody(t *testing.T) {
	var opened *fakeUploadStream
	h := bridge.Upload(bridge.UploadOptions{ChunkSize: 4}, func(_ context.Context, _ *http.Request) (bridge.UploadStream, error) {
		opened = &fakeUploadStream{}
		return opened, nil
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader("abcdefghij")))
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d body=%s", rec.Code, rec.Body.String())
	}
	// 10 字节按 4 分帧：4/4/2。
	if len(opened.chunks) != 3 || string(opened.chunks[0]) != "abcd" || string(opened.chunks[2]) != "ij" {
		t.Fatalf("chunks = %q", opened.chunks)
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["frames"] != float64(3) || resp["bytes"] != float64(10) {
		t.Fatalf("resp = %v", resp)
	}
}

func TestUploadMapsStatusErrors(t *testing.T) {
	h := bridge.Upload(bridge.UploadOptions{ChunkSize: 4}, func(_ context.Context, _ *http.Request) (bridge.UploadStream, error) {
		return nil, status.Error(codes.NotFound, "target missing")
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader("x")))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("code = %d", rec.Code)
	}

	h2 := bridge.Upload(bridge.UploadOptions{ChunkSize: 4}, func(_ context.Context, _ *http.Request) (bridge.UploadStream, error) {
		return nil, context.DeadlineExceeded // 非 status 错误 → Internal 脱敏
	})
	rec2 := httptest.NewRecorder()
	h2.ServeHTTP(rec2, httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader("x")))
	if rec2.Code != http.StatusInternalServerError || strings.Contains(rec2.Body.String(), "Deadline") {
		t.Fatalf("code = %d body = %s", rec2.Code, rec2.Body.String())
	}
}

func TestUploadBodyLimit413(t *testing.T) {
	h := bridge.Upload(bridge.UploadOptions{ChunkSize: 4}, func(_ context.Context, _ *http.Request) (bridge.UploadStream, error) {
		return &fakeUploadStream{}, nil
	})
	// 模拟 server body limit 中间件：8 字节上限，投递 16 字节。
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 8)
		h.ServeHTTP(w, r)
	})
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(strings.Repeat("x", 16))))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("code = %d, want 413", rec.Code)
	}
}

func dialWS(t *testing.T, h http.Handler) *websocket.Conn {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	conn, _, err := websocket.Dial(context.Background(), "ws://"+srv.Listener.Addr().String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(websocket.StatusNormalClosure, "") })
	return conn
}

func TestWSEnvelopeEcho(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := bridge.Upgrade(w, r, bridge.WSOptions{PingInterval: -1})
		if err != nil {
			return
		}
		_ = session.Serve(r.Context(), func(ctx context.Context, env bridge.Envelope) error {
			return session.Write(ctx, bridge.Envelope{Type: "ack", Payload: env.Payload})
		})
	})
	conn := dialWS(t, h)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := conn.Write(ctx, websocket.MessageText, []byte(`{"type":"ping","payload":{"n":1}}`)); err != nil {
		t.Fatal(err)
	}
	msgType, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if msgType != websocket.MessageText {
		t.Fatalf("message type = %v", msgType)
	}
	var env bridge.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	if env.Type != "ack" || string(env.Payload) != `{"n":1}` {
		t.Fatalf("envelope = %+v", env)
	}
}

func TestWSReauthFailureCloses1008(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := bridge.Upgrade(w, r, bridge.WSOptions{
			PingInterval: -1,
			Reauth:       func(context.Context) error { return status.Error(codes.Unauthenticated, "expired") },
		})
		if err != nil {
			return
		}
		_ = session.Serve(r.Context(), func(context.Context, bridge.Envelope) error { return nil })
	})
	conn := dialWS(t, h)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := conn.Write(ctx, websocket.MessageText, []byte(`{"type":"hello"}`)); err != nil {
		t.Fatal(err)
	}
	_, _, err := conn.Read(ctx)
	if websocket.CloseStatus(err) != websocket.StatusCode(1008) {
		t.Fatalf("close status = %v (err=%v), want 1008", websocket.CloseStatus(err), err)
	}
}

func TestWSHandlerErrorSendsSanitizedEnvelopeThenCloses(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := bridge.Upgrade(w, r, bridge.WSOptions{PingInterval: -1})
		if err != nil {
			return
		}
		_ = session.Serve(r.Context(), func(context.Context, bridge.Envelope) error {
			return status.Error(codes.Internal, "boom")
		})
	})
	conn := dialWS(t, h)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := conn.Write(ctx, websocket.MessageText, []byte(`{"type":"go"}`)); err != nil {
		t.Fatal(err)
	}
	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var env bridge.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	if env.Type != "error" || strings.Contains(string(env.Payload), "boom") {
		t.Fatalf("envelope = %+v, want sanitized error", env)
	}
	// 随后服务端以 1011 关闭。
	_, _, err = conn.Read(ctx)
	if websocket.CloseStatus(err) != websocket.StatusCode(1011) {
		t.Fatalf("close status = %v, want 1011", websocket.CloseStatus(err))
	}
}
