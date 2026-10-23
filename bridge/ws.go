package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// WSOptions 是 WebSocket 会话的配置。
type WSOptions struct {
	// Reauth 在每条入站消息前复验凭证（票据短 TTL 场景的周期复验：过期或
	// 撤销即以 1008 断开）。nil = 仅升级时经 extra route 认证中间件验证一次。
	Reauth func(ctx context.Context) error
	// PingInterval 是服务端心跳周期；默认 30s；负值关闭。
	PingInterval time.Duration
	// MaxMessageBytes 是单条入站消息上限；默认 1MiB。超限断开（1009）。
	MaxMessageBytes int64
}

// Envelope 是 WS 双向消息的统一信封：Type 区分消息类别，Payload 由项目
// schema 解释。框架自身只使用 "error"（handler 出错时的通用错误消息）。
type Envelope struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// WSSession 是一次 WebSocket 会话（Upgrade 成功后获得）。
type WSSession struct {
	conn *websocket.Conn
	opts WSOptions
}

// Upgrade 完成 WebSocket 握手并返回会话。挂在 extra route 上时，升级前
// 的认证/授权已由中间件执行；浏览器侧凭证经 authn.WithQueryTicket 票据。
func Upgrade(w http.ResponseWriter, r *http.Request, opts WSOptions) (*WSSession, error) {
	if opts.PingInterval == 0 {
		opts.PingInterval = 30 * time.Second
	}
	if opts.MaxMessageBytes == 0 {
		opts.MaxMessageBytes = 1 << 20
	}
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return nil, fmt.Errorf("bridge: websocket accept: %w", err)
	}
	conn.SetReadLimit(opts.MaxMessageBytes)
	return &WSSession{conn: conn, opts: opts}, nil
}

// Write 向客户端写一条信封消息。
func (s *WSSession) Write(ctx context.Context, env Envelope) error {
	data, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("bridge: ws encode: %w", err)
	}
	if err := s.conn.Write(ctx, websocket.MessageText, data); err != nil {
		return fmt.Errorf("bridge: ws write: %w", err)
	}
	return nil
}

// Close 以给定状态码关闭会话。
func (s *WSSession) Close(code websocket.StatusCode, reason string) error {
	return s.conn.Close(code, reason)
}

// Serve 运行读循环：逐条 Read → Reauth（如配置）→ handler。handler 返回
// nil 继续循环；返回错误时向客户端写通用 error 信封（不泄露内部细节——
// 需要下发业务错误的 handler 自行 Write 后再返回错误）并以 1011 断开。
// 客户端正常断开返回 nil；ctx 取消时连接关闭后返回 ctx 错误。
func (s *WSSession) Serve(ctx context.Context, handler func(ctx context.Context, env Envelope) error) error {
	if s.opts.PingInterval > 0 {
		go func() {
			ticker := time.NewTicker(s.opts.PingInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
					if err := s.conn.Ping(pingCtx); err != nil {
						cancel()
						return
					}
					cancel()
				}
			}
		}()
	}
	for {
		msgType, data, err := s.conn.Read(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if websocket.CloseStatus(err) != -1 {
				// 客户端正常/主动断开。
				return nil
			}
			return fmt.Errorf("bridge: ws read: %w", err)
		}
		if msgType != websocket.MessageText {
			_ = s.conn.Close(websocket.StatusCode(1003), "text frames only")
			return fmt.Errorf("bridge: ws read: binary frames not supported")
		}
		var env Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			_ = s.Write(ctx, Envelope{Type: "error", Payload: mustJSON(map[string]string{"message": "malformed envelope"})})
			continue
		}
		if s.opts.Reauth != nil {
			if err := s.opts.Reauth(ctx); err != nil {
				_ = s.conn.Close(websocket.StatusCode(1008), "credentials expired")
				return status.Error(codes.Unauthenticated, "bridge: ws reauth failed")
			}
		}
		if err := handler(ctx, env); err != nil {
			_ = s.Write(ctx, Envelope{Type: "error", Payload: mustJSON(map[string]string{"message": "internal error"})})
			_ = s.conn.Close(websocket.StatusCode(1011), "handler error")
			return fmt.Errorf("bridge: ws handler: %w", err)
		}
	}
}

func mustJSON(v any) json.RawMessage {
	data, _ := json.Marshal(v)
	return data
}
