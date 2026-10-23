// resource.go 提供资源实例寻址门（torchwood `databases:blog` 形态）的官方
// 范式：Requirement 声明"本方法寻址 <resource> 类资源"，运行期从请求提取
// 目标实例 ID，与 principal 的 scope 集合比对。
//
// 与 scope.Kind 的分工：scope.Kind 做操作级（resource:op 是否放行该方向）；
// ResourceKind 做实例级（请求寻址的目标实例是否被授权）。两个 kind 可同链
// 注册叠加使用——操作门 + 实例门是 torchwood SERVER 档的完整语义。
//
// Requirement 值两种形态：
//
//	values: ["databases"]        实例门（任意方向）
//	values: ["databases:read"]   方向感知实例门：带方向后缀的实例 token
//	                             （databases:blog.read）仅在方向一致时放行
//
// scope token 语义（本 kind 视角）：
//
//	databases           资源整体授权，寻址任意实例放行（任意方向）
//	databases:*         同上（显式通配）
//	databases:blog      授予实例 blog（任意方向）
//	databases:blog.read 授予实例 blog 的 read 方向（仅方向感知门放行；
//	                     无方向门（"databases" 声明）不剥后缀，不授予）
//	databases:read      操作级 token，不授予实例寻址（操作级由 scope.Kind 判定）
//	*                   全局通配（可用 DisallowWildcard 关闭）
//
// 实例 ID 与已知 op（read/write/admin）同名时按 op 解释；实例命名是域内
// 约定，不要用这三个词做 ID。实例段允许携带 "." 后缀方向（cutLast 语义）；
// 后缀不是已知 op 的 "." 一律视作实例 ID 的一部分（dotted id）。
package scope

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/lynx-go/grpcapi/policy"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// ResourceOptions 是 resource kind 的配置。
type ResourceOptions struct {
	// Claim 是 Principal 中承载 scope 的 claim 名；默认 "scopes"（与
	// scope.Kind 共用同一 claim，两个门读同一份授权面）。
	Claim string
	// ID 从请求提取目标实例标识：proto.Message（gRPC）或 *http.Request
	// （extra route）。必填；返回错误按 Internal fail-closed。取值助手见
	// FieldID / QueryID / PathID。
	ID func(req any) (string, error)
	// VocabularyDomain 是资源名词表域；默认 "resource"。
	VocabularyDomain string
	// RequireVocabulary 为 true 时，声明的资源名必须注册词表。
	RequireVocabulary bool
	// DisallowWildcard 为 true 时拒绝 "*" 通配。
	DisallowWildcard bool
}

func (o ResourceOptions) claim() string {
	if o.Claim == "" {
		return "scopes"
	}
	return o.Claim
}

func (o ResourceOptions) domain() string {
	if o.VocabularyDomain == "" {
		return "resource"
	}
	return o.VocabularyDomain
}

// ResourceKind 构造名为 "resource" 的 RequirementKind。
//
// Requirement 形态：{kind: "resource", values: ["databases"]}——values 必须
// 恰有一个声明值："<resource>"（实例门，任意方向）或 "<resource>:<op>"
//（方向感知实例门，op ∈ read/write/admin；一个方法寻址一种资源）。
// ID 为 nil 返回错误：缺提取器的实例门没有求值语义。
func ResourceKind(opts ResourceOptions) (policy.RequirementKind, error) {
	if opts.ID == nil {
		return policy.RequirementKind{}, fmt.Errorf("scope: ResourceOptions.ID is required (see FieldID/QueryID/PathID)")
	}
	return policy.RequirementKind{
		Name:               "resource",
		DefaultMatch:       policy.MatchAny,
		RequiresVocabulary: opts.RequireVocabulary,
		Validate: func(req policy.Requirement, vocab policy.Vocabulary) error {
			if len(req.Values) != 1 {
				return fmt.Errorf("resource requires exactly one value (the addressed resource), got %d", len(req.Values))
			}
			resource, _, err := ParseResourceValue(req.Values[0])
			if err != nil {
				return err
			}
			if resource == "" || resource == "*" || resource == "all" {
				return fmt.Errorf("resource value %q is not a concrete resource name", req.Values[0])
			}
			if strings.ContainsAny(resource, ": ") {
				return fmt.Errorf("resource name %q must not contain ':' or spaces", resource)
			}
			domain := req.Vocabulary
			if domain == "" {
				domain = opts.domain()
			}
			if opts.RequireVocabulary && !vocab.Has(domain) {
				return fmt.Errorf("resource requires vocabulary domain %q, but it is not registered", domain)
			}
			if vocab.Has(domain) && !vocab.Contains(domain, resource) {
				return fmt.Errorf("resource %q is not in vocabulary domain %q", resource, domain)
			}
			return nil
		},
		Evaluate: func(_ context.Context, ec policy.EvalContext, req policy.Requirement) (bool, error) {
			if ec.Principal == nil {
				return false, nil
			}
			resource, op, err := ParseResourceValue(req.Values[0])
			if err != nil {
				// 求值期再守一道（自定义构造的 Set 不经 Build 校验）。
				return false, err
			}
			target, err := opts.ID(ec.Request)
			if err != nil {
				return false, fmt.Errorf("resource: extract target id: %w", err)
			}
			if target == "" {
				// 配置了实例门的方法，请求必须携带可提取的目标；空目标
				// 视为策略装配错误，fail-closed 而不是静默放行。
				return false, fmt.Errorf("resource: request carries no target id for %q", req.Values[0])
			}
			set := Set(ec.Principal.Claim(opts.claim()))
			return GrantsInstanceFor(set, resource, target, op, !opts.DisallowWildcard), nil
		},
	}, nil
}

// ParseResourceValue 解析声明值 "<resource>" 或 "<resource>:<op>"；op 只能
// 是 read/write/admin（空 = 不校验方向）。声明值携带非 op 后缀（如
// "databases:blog"）报错——实例寻址属 principal 授权面，不属声明面。
func ParseResourceValue(value string) (resource, op string, err error) {
	res, op, has := cutLast(value, ":")
	if !has {
		return value, "", nil
	}
	if res == "" || !isOp(op) {
		return "", "", fmt.Errorf("resource value %q must be <resource> or <resource>:<op> (read/write/admin)", value)
	}
	return res, op, nil
}

// GrantsInstance 报告 scope 集合是否授权寻址 resource 的 target 实例。
// 导出供项目自定义 Decider 复用同一语义。
func GrantsInstance(set Set, resource, target string, allowWildcard bool) bool {
	return GrantsInstanceFor(set, resource, target, "", allowWildcard)
}

// GrantsInstanceFor 报告 scope 集合是否授权以 op 方向寻址 resource 的
// target 实例（torchwood T-02「单 token = 方向 + 实例」合取语义）：
//   - 资源整体授权（databases）与无后缀实例 token（databases:blog）对
//     任意方向放行；
//   - 带方向后缀的实例 token（databases:blog.read）仅在实例命中且方向与
//     op 一致时放行；
//   - 操作级 token（databases:read）不授予实例寻址（操作级由 scope.Kind
//     判定）；
//   - op 为空等价 GrantsInstance（不剥实例段方向后缀——向后兼容不变量）。
// 导出供项目自定义 Decider 复用同一语义。
func GrantsInstanceFor(set Set, resource, target, op string, allowWildcard bool) bool {
	for _, token := range set {
		if token == "*" || token == "all" {
			if allowWildcard {
				return true
			}
			continue
		}
		res, seg, hasSeg := splitToken(token)
		if res != resource {
			continue
		}
		switch {
		case !hasSeg:
			// 资源整体授权。
			return true
		case seg == "*":
			return true
		case isOp(seg):
			// 操作级 token（read/write/admin），不授予实例寻址。
			continue
		}
		if op != "" {
			// 方向感知：剥实例段的方向后缀，方向须与 op 一致。
			if inst, suffix, ok := cutLast(seg, "."); ok && isOp(suffix) {
				if inst == target && suffix == op {
					return true
				}
				continue
			}
		}
		if seg == target {
			// 无方向后缀的实例 token = 全方向。
			return true
		}
	}
	return false
}

// FieldID 构造按字段名提取实例 ID 的 ID 函数：proto.Message 按序尝试字段
// （接受 string/整数，snake_case 与 Go 名等价），*http.Request 回落同名
// query 参数。全部缺失返回错误（fail-closed）。
func FieldID(fields ...string) func(any) (string, error) {
	if len(fields) == 0 {
		fields = []string{"id"}
	}
	return func(req any) (string, error) {
		switch v := req.(type) {
		case protoreflect.ProtoMessage:
			m := v.ProtoReflect()
			for _, name := range fields {
				fd := fieldDescriptor(m, name)
				if fd == nil {
					continue
				}
				value := m.Get(fd)
				switch fd.Kind() {
				case protoreflect.StringKind:
					if s := value.String(); s != "" {
						return s, nil
					}
				case protoreflect.Int32Kind, protoreflect.Int64Kind,
					protoreflect.Uint32Kind, protoreflect.Uint64Kind:
					return fmt.Sprintf("%d", value.Int()), nil
				}
			}
			return "", fmt.Errorf("no id field %v on %s", fields, m.Descriptor().FullName())
		case *http.Request:
			for _, name := range fields {
				if s := v.URL.Query().Get(name); s != "" {
					return s, nil
				}
			}
			return "", fmt.Errorf("no id query param %v", fields)
		default:
			return "", fmt.Errorf("unsupported request type %T (want proto.Message or *http.Request)", req)
		}
	}
}

// QueryID 构造从 *http.Request query 参数提取实例 ID 的 ID 函数。
func QueryID(param string) func(any) (string, error) {
	return func(req any) (string, error) {
		r, ok := req.(*http.Request)
		if !ok {
			return "", fmt.Errorf("resource: QueryID needs *http.Request, got %T", req)
		}
		s := r.URL.Query().Get(param)
		if s == "" {
			return "", fmt.Errorf("resource: query param %q is empty", param)
		}
		return s, nil
	}
}

// PathID 构造从 *http.Request 路径参数提取实例 ID 的 ID 函数（Go 1.22
// ServeMux pattern 命名段，如 /v1/databases/{id}；extra route 挂载时可用）。
func PathID(name string) func(any) (string, error) {
	return func(req any) (string, error) {
		r, ok := req.(*http.Request)
		if !ok {
			return "", fmt.Errorf("resource: PathID needs *http.Request, got %T", req)
		}
		s := r.PathValue(name)
		if s == "" {
			return "", fmt.Errorf("resource: path value %q is empty", name)
		}
		return s, nil
	}
}

// fieldDescriptor 按字段名查找（优先 proto 字段名，兼容 Go 命名）。
func fieldDescriptor(m protoreflect.Message, name string) protoreflect.FieldDescriptor {
	fields := m.Descriptor().Fields()
	if fd := fields.ByName(protoreflect.Name(name)); fd != nil {
		return fd
	}
	if fd := fields.ByJSONName(name); fd != nil {
		return fd
	}
	return nil
}
