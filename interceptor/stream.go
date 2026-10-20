package interceptor

import (
	"context"

	"google.golang.org/grpc"
)

// wrappedStream 只替换 Context；SendMsg/RecvMsg/Header/Trailer 由嵌入的
// ServerStream 原样转发。
type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *wrappedStream) Context() context.Context { return s.ctx }

// validatingStream 在每次 RecvMsg 后校验消息。
type validatingStream struct {
	grpc.ServerStream
	validator *ValidateInterceptor
}

func (s *validatingStream) RecvMsg(m any) error {
	if err := s.ServerStream.RecvMsg(m); err != nil {
		return err
	}
	return s.validator.validateMessage(m)
}
