package interceptor

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"google.golang.org/grpc/peer"
)

// TrustedProxies 声明可信代理网段。仅当直连 peer 命中这些网段时，
// 才回溯其转发的 X-Forwarded-For / 采纳 X-Real-Ip；否则一律使用 peer
// 自身地址，防止客户端伪造转发头绕过 IP 限流与审计留痕。
// 空列表 = 不信任任何代理。
type TrustedProxies struct {
	prefixes []netip.Prefix
	// invalid 为 true 时信任集整体作废（任何地址都不可信）：用于
	// 配置解析失败时的 fail-closed 兜底（见 NewClientInfo）。
	invalid bool
}

// ParseTrustedProxies 解析 CIDR 列表（也接受裸 IP，按 /32、/128 处理）。
// 需要在启动期暴露配置错误的调用方应先经此函数校验再装配
// ClientInfoConfig（NewClientInfo 自身不返回 error，见其文档）。
func ParseTrustedProxies(cidrs []string) (*TrustedProxies, error) {
	tp := &TrustedProxies{}
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		p, err := netip.ParsePrefix(c)
		if err != nil {
			addr, aerr := netip.ParseAddr(c)
			if aerr != nil {
				return nil, fmt.Errorf("invalid trusted proxy %q: %w", c, err)
			}
			p = netip.PrefixFrom(addr, addr.BitLen())
		}
		tp.prefixes = append(tp.prefixes, p.Masked())
	}
	return tp, nil
}

// Trusted 报告 ip 是否命中可信代理网段。信任集作废（invalid）或 t 为
// nil 时一律 false。
func (t *TrustedProxies) Trusted(ip string) bool {
	if t == nil || t.invalid {
		return false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, p := range t.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// ResolveClientIP 计算有效客户端 IP：仅当直连 peer 命中可信网段时，
// 才逐跳回溯 X-Forwarded-For（无 XFF 退到 X-Real-Ip）；否则一律使用
// peer 自身地址。
func (t *TrustedProxies) ResolveClientIP(peerIP, xff, realIP string) string {
	if t.Trusted(peerIP) {
		if ip := t.clientFromXFF(xff); ip != "" {
			return ip
		}
		if realIP = strings.TrimSpace(realIP); realIP != "" {
			return realIP
		}
	}
	return strings.TrimSpace(peerIP)
}

// clientFromXFF 自右向左逐跳回溯 X-Forwarded-For：每个命中可信网段的
// 地址视为代理并继续向左，第一个不可信地址即认定为客户端——客户端
// 伪造注入的前缀跳在此被截断。全部可信（或全空）时取最左侧非空跳
// （链首即首个代理所见地址）。
//
// 与 torchwood 参考实现（直接取首跳）的差异是刻意的安全加固：首跳
// 取法会把客户端自行携带的伪造跳当作来源，见 DESIGN §5 clientInfo。
func (t *TrustedProxies) clientFromXFF(xff string) string {
	hops := strings.Split(xff, ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop := strings.TrimSpace(hops[i])
		if hop == "" {
			continue
		}
		if !t.Trusted(hop) {
			return hop
		}
	}
	for _, h := range hops {
		if h = strings.TrimSpace(h); h != "" {
			return h
		}
	}
	return ""
}

// FirstForwardedHop 取 X-Forwarded-For 的首个（最靠近客户端的）地址。
// 仅用于无 peer 信息（进程内调用/测试）时的退化取值路径。
func FirstForwardedHop(xff string) string {
	xff = strings.TrimSpace(xff)
	if xff == "" {
		return ""
	}
	if idx := strings.Index(xff, ","); idx >= 0 {
		xff = xff[:idx]
	}
	return strings.TrimSpace(xff)
}

// PeerIPFromAddr 从 "host:port" 形式的对端地址提取 IP 部分。
func PeerIPFromAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// PeerIP 从 gRPC 请求上下文提取直连 peer 的 IP；无 peer 信息时返回空串。
func PeerIP(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		return PeerIPFromAddr(p.Addr.String())
	}
	return ""
}
