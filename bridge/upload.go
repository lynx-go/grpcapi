package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/lynx-go/grpcapi/gateway"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// UploadOptions 是 HTTP body → client-streaming 桥的配置。
type UploadOptions struct {
	// ChunkSize 是分帧大小；默认 1MiB；<=0 使用默认值。
	ChunkSize int
}

// UploadStream 是一次上传会话：open 时建立（通常是 client-streaming RPC 的
// stream 对象），逐帧 Send，Finalize 关闭发送并取最终响应（CloseAndRecv 语义）。
type UploadStream interface {
	Send(ctx context.Context, chunk []byte) error
	Finalize(ctx context.Context) (any, error)
}

// Upload 把 HTTP 请求体分帧桥接到 client-streaming 发送：body 按 ChunkSize
// 切块逐帧 Send，读完 Finalize，响应以 JSON 写出。grpc-gateway 不转码
// client-streaming 注解，本桥补齐该面；策略/认证由所在 extra route 承担。
//
// 错误映射：gRPC status 走 gateway 统一错误体（脱敏/Retry-After 语义一致）；
// 超出路由 body 上限（MaxBytesReader）读失败为 413；客户端断开静默结束。
func Upload(opts UploadOptions, open func(ctx context.Context, r *http.Request) (UploadStream, error)) http.Handler {
	if opts.ChunkSize <= 0 {
		opts.ChunkSize = 1 << 20
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		stream, err := open(ctx, r)
		if err != nil {
			writeStreamError(w, r, err)
			return
		}
		buf := make([]byte, opts.ChunkSize)
		for {
			n, readErr := io.ReadFull(r.Body, buf)
			if n > 0 {
				if err := stream.Send(ctx, buf[:n]); err != nil {
					if ctx.Err() != nil {
						return
					}
					writeStreamError(w, r, err)
					return
				}
			}
			if readErr == nil {
				continue
			}
			if errors.Is(readErr, io.EOF) || errors.Is(readErr, io.ErrUnexpectedEOF) {
				break
			}
			var maxErr *http.MaxBytesError
			if errors.As(readErr, &maxErr) {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			if ctx.Err() != nil {
				return
			}
			writeStreamError(w, r, fmt.Errorf("bridge: read body: %w", readErr))
			return
		}
		resp, err := stream.Finalize(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			writeStreamError(w, r, err)
			return
		}
		data, err := json.Marshal(resp)
		if err != nil {
			writeStreamError(w, r, fmt.Errorf("bridge: encode response: %w", err))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(append(data, '\n'))
	})
}

// writeStreamError 与 gateway 错误语义对齐：status 错误按 code→HTTP 映射 +
// 统一错误体；非 status 错误归 Internal 并脱敏。
func writeStreamError(w http.ResponseWriter, r *http.Request, err error) {
	if st, ok := status.FromError(err); ok && st != nil && st.Code() != codes.Unknown {
		gateway.WriteError(w, r, err, nil)
		return
	}
	gateway.WriteError(w, r, status.Error(codes.Internal, "internal server error"), nil)
}
