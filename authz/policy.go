// Package authz 把 proto 注解声明的 API 授权策略（grpcapi.v1.method_auth /
// service_auth 扩展）收集为运行时 PolicySet，并在构造期做 fail-closed 断言。
//
// 本包是库的机制心脏：零 grpc/lynx 依赖，只依赖 protobuf（descriptor 反射与
// genproto 扩展类型），domain 分层纯净的项目可直接引用。词表主权归项目：
// scope 资源、admin 角色、permissions 一律 string，值域由 Options.Vocabulary
// 与项目断言钩子（Assertion）把守；值域稳定的 AccessLevel / ScopeOp 由本包
// 以枚举持有（DESIGN.md §2 切分原则）。
//
// 导入路径：github.com/lynx-go/grpcapi/authz。
package authz

import (
	"fmt"
	"sort"
)

// AccessLevel 是方法的凭证族门禁（与 proto grpcapi.v1.AccessLevel 编号一一
// 对应，收集期直接按数值转换；0 语义为未声明，构造期报错）。
type AccessLevel int32

const (
	// AccessUnspecified 未声明——收集期 fail-closed（缺注解、服务无缺省档、
	// 显式 UNSPECIFIED 与未登记枚举值都归入此类）。
	AccessUnspecified AccessLevel = iota
	// AccessPublic 匿名可调。
	AccessPublic
	// AccessEndUser 端用户凭证（JWT/session）。
	AccessEndUser
	// AccessServer 服务面：admin 会话（admin_roles）或 scoped API key（scope 把关）。
	AccessServer
	// AccessPermission 角色权限面（permissions 把关；API key 凭证一律拒绝）。
	AccessPermission
	// AccessSystem 内部系统调用（预留档位，v1 禁用，见 DESIGN.md §9，构造期报错）。
	AccessSystem
)

// ScopeOp 是 API key scope 的权限方向。
type ScopeOp string

const (
	ScopeRead  ScopeOp = "read"
	ScopeWrite ScopeOp = "write"
	ScopeAdmin ScopeOp = "admin"
)

// validScopeOps 是 ScopeOp 的值域（词表断言与 ScopeSet 匹配共用）。
var validScopeOps = map[ScopeOp]struct{}{
	ScopeRead:  {},
	ScopeWrite: {},
	ScopeAdmin: {},
}

// isRegisteredScopeOp 报告 op 是否为已登记方向。
func isRegisteredScopeOp(op ScopeOp) bool {
	_, ok := validScopeOps[op]
	return ok
}

// ScopeRule 是 SERVER 面方法对 API key 凭证开放的 scope 门。
type ScopeRule struct {
	// Resource 是资源名（词表主权在项目，构造期经 Vocabulary 校验）。
	Resource string
	// Op 是权限方向，必须是三个已登记值之一（空串经断言 fail-closed 拒绝）。
	Op ScopeOp
}

// MethodPolicy 是单个方法的完整授权策略（proto 声明的运行时投影）。
type MethodPolicy struct {
	// Method 是 "/pkg.Svc/Method" 全名形态；Service 是 "/pkg.Svc" 形态。
	Method, Service string
	// Access 是凭证族门禁。
	Access AccessLevel
	// Permissions 原样透传（值域主权在项目，库不做归一化）。
	Permissions []string
	// AdminRoles 原样透传（值域主权在项目）。
	AdminRoles []string
	// Scope 是 SERVER 面 API key 门；nil = 不对 key 开放。
	Scope *ScopeRule
	// RequestFields 是请求消息全部字段名，字典序（排序投影）。
	RequestFields []string
	// IsStreaming 存在任一方向的 streaming 即为 true（v1 默认 fail-closed）。
	IsStreaming bool
}

// PolicySet 是全量方法策略注册表（由 Build 构造，注入各执行点）。
type PolicySet struct {
	methods map[string]MethodPolicy
}

// NewPolicySet 构造注册表；重复 Method 报错。构造后集合不可变——调用方
// 不得修改传入策略内的切片。
func NewPolicySet(policies ...MethodPolicy) (*PolicySet, error) {
	m := make(map[string]MethodPolicy, len(policies))
	for _, p := range policies {
		if _, dup := m[p.Method]; dup {
			return nil, fmt.Errorf("duplicate method policy %s", p.Method)
		}
		m[p.Method] = p
	}
	return &PolicySet{methods: m}, nil
}

// Get 返回单方法策略（浅拷贝；切片字段只读，不得修改）。
func (s *PolicySet) Get(method string) (MethodPolicy, bool) {
	if s == nil {
		return MethodPolicy{}, false
	}
	p, ok := s.methods[method]
	return p, ok
}

// Methods 返回全部策略，按 Method 字典序排序（输出稳定，供矩阵测试与
// 文档生成遍历）。
func (s *PolicySet) Methods() []MethodPolicy {
	if s == nil {
		return nil
	}
	out := make([]MethodPolicy, 0, len(s.methods))
	for _, p := range s.methods {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Method < out[j].Method })
	return out
}

// ScopeRule 返回方法对 API key 开放的 scope 规则；未登记、非 SERVER 面
// 或未声明 scope 返回 nil（fail-closed）。
func (s *PolicySet) ScopeRule(method string) *ScopeRule {
	p, ok := s.Get(method)
	if !ok || p.Access != AccessServer || p.Scope == nil {
		return nil
	}
	rule := *p.Scope
	return &rule
}

// AllowedAdminRoles 返回 SERVER 面方法允许的 admin 角色集；非 SERVER 面
// 返回 nil。SERVER 面未声明角色返回 nil，语义为不限角色。
func (s *PolicySet) AllowedAdminRoles(method string) []string {
	p, ok := s.Get(method)
	if !ok || p.Access != AccessServer {
		return nil
	}
	return append([]string(nil), p.AdminRoles...)
}
