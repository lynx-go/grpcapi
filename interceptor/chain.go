package interceptor

import (
	"fmt"
	"strings"

	"google.golang.org/grpc"
)

// 内置 Stage 名。
const (
	StageRecovery   = "recovery"
	StageRequestID  = "requestid"
	StageClientInfo = "clientinfo"
	StageAuthn      = "authn"
	StageRateLimit  = "ratelimit"
	StageAudit      = "audit"
	StageUsage      = "usage"
	StageAuthz      = "authz"
	StageValidate   = "validate"
)

// 内置 Stage 顺序（升序 = 执行顺序）。
const (
	OrderRecovery   = 0
	OrderRequestID  = 10
	OrderClientInfo = 20
	OrderAuthn      = 30
	OrderRateLimit  = 40
	OrderAudit      = 50
	OrderUsage      = 60
	OrderAuthz      = 70
	OrderValidate   = 80
)

// Stage 是链上的一条拦截器，可同时提供 unary/stream 实现。
type Stage struct {
	Name   string
	Order  int
	Unary  grpc.UnaryServerInterceptor
	Stream grpc.StreamServerInterceptor
}

// ChainOptions 是严格的链约束；零值 = 只校验名字/顺序/非空。
type ChainOptions struct {
	First    string
	Last     string
	Required []string
}

// DefaultChainOptions 是 torchwood 风格的严格默认：clientinfo 打头、
// validate 收尾。
func DefaultChainOptions() ChainOptions {
	return ChainOptions{
		First:    StageClientInfo,
		Last:     StageValidate,
		Required: []string{StageClientInfo, StageValidate},
	}
}

// Chain 是不可变拦截器链。
type Chain struct {
	stages []Stage
}

// Assemble 按输入顺序装配；校验名字唯一、Order 单调不减、每 Stage 非空。
func Assemble(stages ...Stage) (*Chain, error) {
	return AssembleWith(ChainOptions{}, stages...)
}

// AssembleWith 在 Assemble 基础上校验 First/Last/Required。
func AssembleWith(opts ChainOptions, stages ...Stage) (*Chain, error) {
	if len(stages) == 0 {
		return nil, fmt.Errorf("interceptor chain: no stages")
	}
	seen := make(map[string]struct{}, len(stages))
	prev := -1
	for i, st := range stages {
		if st.Name == "" {
			return nil, fmt.Errorf("interceptor chain: stage %d has empty name", i)
		}
		if _, dup := seen[st.Name]; dup {
			return nil, fmt.Errorf("interceptor chain: duplicate stage %q", st.Name)
		}
		seen[st.Name] = struct{}{}
		if st.Unary == nil && st.Stream == nil {
			return nil, fmt.Errorf("interceptor chain: stage %q has no interceptor", st.Name)
		}
		if st.Order < prev {
			return nil, fmt.Errorf("interceptor chain: stage %q order %d goes backwards after %d", st.Name, st.Order, prev)
		}
		prev = st.Order
	}
	if opts.First != "" && stages[0].Name != opts.First {
		return nil, fmt.Errorf("interceptor chain: first stage must be %q, got %q", opts.First, stages[0].Name)
	}
	if opts.Last != "" {
		last := stages[len(stages)-1].Name
		if last != opts.Last {
			return nil, fmt.Errorf("interceptor chain: last stage must be %q, got %q", opts.Last, last)
		}
	}
	for _, name := range opts.Required {
		if _, ok := seen[name]; !ok {
			return nil, fmt.Errorf("interceptor chain: required stage %q is missing", name)
		}
	}
	out := make([]Stage, len(stages))
	copy(out, stages)
	return &Chain{stages: out}, nil
}

// Unary 返回 unary 拦截器切片（保持 Stage 顺序）。
func (c *Chain) Unary() []grpc.UnaryServerInterceptor {
	if c == nil {
		return nil
	}
	out := make([]grpc.UnaryServerInterceptor, 0, len(c.stages))
	for _, st := range c.stages {
		if st.Unary != nil {
			out = append(out, st.Unary)
		}
	}
	return out
}

// Stream 返回 stream 拦截器切片（保持 Stage 顺序）。
func (c *Chain) Stream() []grpc.StreamServerInterceptor {
	if c == nil {
		return nil
	}
	out := make([]grpc.StreamServerInterceptor, 0, len(c.stages))
	for _, st := range c.stages {
		if st.Stream != nil {
			out = append(out, st.Stream)
		}
	}
	return out
}

// ServerOptions 返回可直接传给 grpc.NewServer 的 chain 选项。
func (c *Chain) ServerOptions() []grpc.ServerOption {
	var opts []grpc.ServerOption
	if u := c.Unary(); len(u) > 0 {
		opts = append(opts, grpc.ChainUnaryInterceptor(u...))
	}
	if s := c.Stream(); len(s) > 0 {
		opts = append(opts, grpc.ChainStreamInterceptor(s...))
	}
	return opts
}

// Has 报告是否存在带 unary 实现的指定 Stage。
func (c *Chain) Has(name string) bool {
	for _, st := range c.stages {
		if st.Name == name && st.Unary != nil {
			return true
		}
	}
	return false
}

// HasStream 报告是否存在带 stream 实现的指定 Stage。
func (c *Chain) HasStream(name string) bool {
	for _, st := range c.stages {
		if st.Name == name && st.Stream != nil {
			return true
		}
	}
	return false
}

// HasStage 报告 Stage 是否存在（不论 transport）。
func (c *Chain) HasStage(name string) bool {
	for _, st := range c.stages {
		if st.Name == name {
			return true
		}
	}
	return false
}

// Stages 返回 Stage 的副本。
func (c *Chain) Stages() []Stage {
	if c == nil {
		return nil
	}
	out := make([]Stage, len(c.stages))
	copy(out, c.stages)
	return out
}

// String 便于启动日志。
func (c *Chain) String() string {
	if c == nil {
		return "<nil>"
	}
	names := make([]string, 0, len(c.stages))
	for _, st := range c.stages {
		names = append(names, st.Name)
	}
	return strings.Join(names, " -> ")
}
