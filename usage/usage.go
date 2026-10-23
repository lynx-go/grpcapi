// Package usage 提供内存用量计量参考实现，填 interceptor.UsageStage 槽位。
//
// 按方法累计请求数与错误数，供配额检查/计费粗计量消费。进程内计数、重启
// 清零；需要持久化或按主体计费精度的项目经 Snapshot 定期抓取后自行落库。
package usage

import (
	"context"
	"sync"

	"github.com/lynx-go/grpcapi/interceptor"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Counters 是单个方法键的累计值。
type Counters struct {
	Requests uint64
	Errors   uint64
}

// Meter 是按方法计数的用量表。
type Meter struct {
	mu   sync.Mutex
	rows map[string]*Counters
}

// New 构造用量表。
func New() *Meter {
	return &Meter{rows: map[string]*Counters{}}
}

// Unary 返回 unary 计量拦截器。
func (m *Meter) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		resp, err := handler(ctx, req)
		m.count(info.FullMethod, err)
		return resp, err
	}
}

// Stream 返回 stream 计量拦截器（每次流建立计一次）。
func (m *Meter) Stream() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		err := handler(srv, ss)
		m.count(info.FullMethod, err)
		return err
	}
}

func (m *Meter) count(method string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	row, ok := m.rows[method]
	if !ok {
		row = &Counters{}
		m.rows[method] = row
	}
	row.Requests++
	if err != nil && status.Code(err) != codes.OK {
		row.Errors++
	}
}

// Snapshot 返回当前计数的深拷贝。
func (m *Meter) Snapshot() map[string]Counters {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]Counters, len(m.rows))
	for k, v := range m.rows {
		out[k] = *v
	}
	return out
}

// SnapshotAndReset 返回计数并清零（抓取周期消费）。
func (m *Meter) SnapshotAndReset() map[string]Counters {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]Counters, len(m.rows))
	for k, v := range m.rows {
		out[k] = *v
	}
	m.rows = map[string]*Counters{}
	return out
}

// Stage 返回可直接进 interceptor.Assemble 的 usage Stage。
func (m *Meter) Stage() interceptor.Stage {
	return interceptor.UsageStage(m.Unary(), m.Stream())
}
