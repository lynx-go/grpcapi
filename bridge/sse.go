package bridge

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// SSEOptions 是 SSE 流的配置。
type SSEOptions struct {
	// KeepAlive 是注释行心跳周期（对抗代理/负载均衡空闲超时）；0 = 不发。
	KeepAlive time.Duration
	// RetryHint 是连接建立时下发的重连建议毫秒数（retry: 行）。
	RetryHint int
	// OnError 把流式业务错误映射为出站错误事件；返回 false 表示不写任何
	// 事件、直接断开。nil = 写通用 "error" 事件（不泄露内部细节）。
	OnError func(err error) (message string, write bool)
}

// SSEWriter 按事件流规范（text/event-stream）写事件；并发安全（心跳与业务
// 写共享一把锁）。
type SSEWriter struct {
	w       http.ResponseWriter
	flusher http.Flusher
	mu      sync.Mutex
}

// SSE 初始化 SSE 响应：写响应头并返回写入器。ResponseWriter 不支持 Flusher
// 时返回错误（中间件链里需要 http.Flusher 透传）。
func SSE(w http.ResponseWriter) (*SSEWriter, error) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		return nil, fmt.Errorf("bridge: SSE requires a flushing ResponseWriter")
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	// nginx 等反代会缓冲响应体，SSE 必须显式关闭。
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()
	return &SSEWriter{w: w, flusher: flusher}, nil
}

// Event 写一条命名事件；data 按行拆分为多个 data: 行（SSE 规范）。
func (s *SSEWriter) Event(name string, data []byte) error {
	return s.EventWithID("", name, data)
}

// EventWithID 写带 id 的命名事件；id 为空时省略 id 行。
func (s *SSEWriter) EventWithID(id, name string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var b strings.Builder
	if id != "" {
		fmt.Fprintf(&b, "id: %s\n", id)
	}
	if name != "" {
		fmt.Fprintf(&b, "event: %s\n", name)
	}
	for _, line := range splitLines(string(data)) {
		fmt.Fprintf(&b, "data: %s\n", line)
	}
	b.WriteString("\n")
	if _, err := s.w.Write([]byte(b.String())); err != nil {
		return fmt.Errorf("bridge: sse write: %w", err)
	}
	s.flusher.Flush()
	return nil
}

// Comment 写注释行（心跳）。
func (s *SSEWriter) Comment(line string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := fmt.Fprintf(s.w, ": %s\n\n", line); err != nil {
		return fmt.Errorf("bridge: sse comment: %w", err)
	}
	s.flusher.Flush()
	return nil
}

// Retry 写重连建议毫秒数。
func (s *SSEWriter) Retry(ms int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := fmt.Fprintf(s.w, "retry: %d\n\n", ms); err != nil {
		return fmt.Errorf("bridge: sse retry: %w", err)
	}
	s.flusher.Flush()
	return nil
}

// SSEHandler 构造完整 SSE 端点：初始化流、按配置发心跳/retry 建议、运行
// stream 回调。回调返回即断开；业务错误经 OnError（或默认通用 error 事件）
// 下发后关闭。
func SSEHandler(stream func(s *SSEWriter, r *http.Request) error, opts SSEOptions) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw, err := SSE(w)
		if err != nil {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		if opts.RetryHint > 0 {
			_ = sw.Retry(opts.RetryHint)
		}
		if opts.KeepAlive > 0 {
			stop := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				ticker := time.NewTicker(opts.KeepAlive)
				defer ticker.Stop()
				for {
					select {
					case <-stop:
						return
					case <-r.Context().Done():
						return
					case <-ticker.C:
						_ = sw.Comment("keep-alive")
					}
				}
			}()
			// handler 返回前必须等心跳 goroutine 退净：net/http 在 handler
			// 返回后会动响应对象，晚到的写会与之竞争。
			defer func() { close(stop); wg.Wait() }()
		}
		if err := stream(sw, r); err != nil && r.Context().Err() == nil {
			message, write := "internal error", true
			if opts.OnError != nil {
				message, write = opts.OnError(err)
			}
			if write {
				_ = sw.Event("error", []byte(message))
			}
		}
	})
}

// splitLines 按 \n 拆行并去掉 \r（SSE 规范：CR LF 只按 LF 计）。
func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return []string{""}
	}
	return strings.Split(s, "\n")
}
