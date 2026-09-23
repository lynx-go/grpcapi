package interceptor

import (
	"fmt"

	"google.golang.org/grpc"
)

// Slot 标记拦截器在链上的职能位。Assemble 依据 Slot 做构造期顺序断言：
// 配置错误启动即红，而非静默产出一条语义错乱的链。
type Slot int

const (
	// SlotClientInfo 必须打头：后续拦截器（限流/审计）都依赖 ctx 中的
	// 客户端信息。
	SlotClientInfo Slot = iota
	SlotAuth
	SlotRateLimit
	SlotAudit
	SlotUsage
	// SlotValidate 必须收尾：校验失败的请求同样要产生审计行并计入用量。
	SlotValidate
	// SlotCount 是哨兵，不是合法槽位。
	SlotCount
)

var slotNames = [...]string{
	SlotClientInfo: "clientinfo",
	SlotAuth:       "auth",
	SlotRateLimit:  "ratelimit",
	SlotAudit:      "audit",
	SlotUsage:      "usage",
	SlotValidate:   "validate",
}

func (s Slot) String() string {
	if s < 0 || s >= SlotCount {
		return fmt.Sprintf("slot(%d)", int(s))
	}
	return slotNames[s]
}

// ChainItem 是待装配的单条拦截器及其职能位。
type ChainItem struct {
	Slot        Slot
	Interceptor grpc.UnaryServerInterceptor
}

// Assemble 按装配顺序构造拦截器切片，并做构造期断言（启动即红，不
// 静默）：
//
//   - Slot 必须单调不减：同一 slot 允许多条（如多层限流），乱序或
//     回退（如 auth 之后出现 clientinfo）报错；
//   - SlotClientInfo 必须存在且打头；
//   - SlotValidate 必须存在且收尾；
//   - 中间位允许 auth/ratelimit/audit/usage 的任意子集与顺序。
//
// 刻意不是框架：没有注册表、没有选项模式，一个纯函数 + 显式报错。
func Assemble(items ...ChainItem) ([]grpc.UnaryServerInterceptor, error) {
	if len(items) == 0 {
		return nil, fmt.Errorf("interceptor chain: no items")
	}
	prev := Slot(-1)
	out := make([]grpc.UnaryServerInterceptor, 0, len(items))
	for i, item := range items {
		if item.Slot < 0 || item.Slot >= SlotCount {
			return nil, fmt.Errorf("interceptor chain: item %d has invalid slot %s", i, item.Slot)
		}
		if item.Interceptor == nil {
			return nil, fmt.Errorf("interceptor chain: item %d (slot %s) has nil interceptor", i, item.Slot)
		}
		if item.Slot < prev {
			return nil, fmt.Errorf("interceptor chain: item %d slot %s goes backwards after %s", i, item.Slot, prev)
		}
		prev = item.Slot
		out = append(out, item.Interceptor)
	}
	if items[0].Slot != SlotClientInfo {
		return nil, fmt.Errorf("interceptor chain: first item must be %s, got %s", SlotClientInfo, items[0].Slot)
	}
	if last := items[len(items)-1].Slot; last != SlotValidate {
		return nil, fmt.Errorf("interceptor chain: last item must be %s, got %s", SlotValidate, last)
	}
	return out, nil
}
