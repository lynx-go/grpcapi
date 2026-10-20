// Package policy 定义 proto 注解声明的 API 策略 IR：策略、暴露面、操作、
// 词表与可注册的谓词。包本身只依赖 protobuf 反射与 principal，不依赖
// grpc/lynx/gateway，便于 domain 层直接使用。
package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/lynx-go/grpcapi/principal"
)

// Match 是 Requirement 的值匹配语义。
type Match int

const (
	// MatchDefault 表示使用 RequirementKind 的默认匹配语义。
	MatchDefault Match = iota
	// MatchAny 表示 values 中至少一个命中。
	MatchAny
	// MatchAll 表示 values 全部命中。
	MatchAll
)

func (m Match) String() string {
	switch m {
	case MatchAny:
		return "any"
	case MatchAll:
		return "all"
	default:
		return "default"
	}
}

// Requirement 是策略树中的一个谓词。
type Requirement struct {
	// Kind 是已注册的谓词类型（authenticated/claim/role/permission/scope/...）。
	Kind string
	// Vocabulary 是词表域；空 = 按 kind 规则推导。
	Vocabulary string
	// Match 是值匹配语义；MatchDefault 使用 kind 默认。
	Match Match
	// Values 是谓词值（角色、权限、scope、claim 值等）。
	Values []string
	// Params 是 kind 自定义参数（claim 名、表达式等）。
	Params map[string]string
}

// Clone 返回深拷贝。
func (r Requirement) Clone() Requirement {
	out := r
	out.Values = append([]string(nil), r.Values...)
	if len(r.Params) > 0 {
		out.Params = make(map[string]string, len(r.Params))
		for k, v := range r.Params {
			out.Params[k] = v
		}
	}
	return out
}

// Policy 是单个 operation 的有效授权策略。
//
// 有效策略 = preset 展开 + inherit 合并后的结果；Preset/PresetArgs 只保留
// 诊断信息，不参与求值。
type Policy struct {
	Preset     string
	PresetArgs map[string]string
	Anonymous  bool
	Require    []Requirement
	AnyOf      [][]Requirement // 每个内层切片是一个 AND 组
	Forbid     []Requirement
}

// Clone 返回深拷贝。
func (p Policy) Clone() Policy {
	out := p
	out.Require = cloneRequirements(p.Require)
	if len(p.AnyOf) > 0 {
		out.AnyOf = make([][]Requirement, len(p.AnyOf))
		for i, group := range p.AnyOf {
			out.AnyOf[i] = cloneRequirements(group)
		}
	}
	out.Forbid = cloneRequirements(p.Forbid)
	if len(p.PresetArgs) > 0 {
		out.PresetArgs = make(map[string]string, len(p.PresetArgs))
		for k, v := range p.PresetArgs {
			out.PresetArgs[k] = v
		}
	}
	return out
}

func cloneRequirements(in []Requirement) []Requirement {
	if len(in) == 0 {
		return nil
	}
	out := make([]Requirement, len(in))
	for i, r := range in {
		out[i] = r.Clone()
	}
	return out
}

// IsZero 报告策略是否完全未声明。
func (p Policy) IsZero() bool {
	return !p.Anonymous && len(p.Require) == 0 && len(p.AnyOf) == 0 && len(p.Forbid) == 0 && p.Preset == ""
}

// Exposure 是 operation 的对外暴露面。
type Exposure int

const (
	ExposureUnspecified Exposure = iota
	ExposureInternal
	ExposurePublic
	ExposureDeprecated
	ExposureHidden
)

func (e Exposure) String() string {
	switch e {
	case ExposureInternal:
		return "internal"
	case ExposurePublic:
		return "public"
	case ExposureDeprecated:
		return "deprecated"
	case ExposureHidden:
		return "hidden"
	default:
		return "unspecified"
	}
}

// StreamAuthMode 是流式方法的授权粒度。
type StreamAuthMode int

const (
	StreamAuthOpen StreamAuthMode = iota + 1
	StreamAuthPerMessage
)

func (m StreamAuthMode) String() string {
	switch m {
	case StreamAuthPerMessage:
		return "per_message"
	default:
		return "open"
	}
}

// Kind 是 operation 的类型。
type Kind int

const (
	KindGRPC Kind = iota + 1
	KindHTTP
)

func (k Kind) String() string {
	switch k {
	case KindHTTP:
		return "http"
	case KindGRPC:
		return "grpc"
	default:
		return "unknown"
	}
}

// Operation 是策略与路由的统一单位：gRPC method 或 HTTP extra route。
type Operation struct {
	ID          string
	Kind        Kind
	Service     string
	API         string
	Policy      Policy
	Exposure    Exposure
	Label       string
	OperationID string
	Streaming   bool
	StreamAuth  StreamAuthMode
	// RequestFields 是请求消息全部字段名（字典序），供项目断言/迁移消费。
	RequestFields []string
	Metadata      map[string]string
}

// Clone 返回深拷贝。
func (o Operation) Clone() Operation {
	out := o
	out.Policy = o.Policy.Clone()
	out.RequestFields = append([]string(nil), o.RequestFields...)
	if len(o.Metadata) > 0 {
		out.Metadata = make(map[string]string, len(o.Metadata))
		for k, v := range o.Metadata {
			out.Metadata[k] = v
		}
	}
	return out
}

// EffectiveLabel 返回文档/矩阵使用的稳定标签。
func (o Operation) EffectiveLabel() string {
	if o.Label != "" {
		return o.Label
	}
	return Label(o.Policy)
}

// Label 从有效策略派生稳定标签。只用于文档分类，不参与授权判断。
func Label(p Policy) string {
	if p.Preset != "" {
		return p.Preset
	}
	if p.Anonymous {
		return "public"
	}
	if len(p.Require) == 1 && len(p.AnyOf) == 0 && len(p.Forbid) == 0 {
		r := p.Require[0]
		switch r.Kind {
		case "authenticated":
			return "authenticated"
		case "role":
			return "role"
		case "permission":
			return "permission"
		case "scope":
			return "scope"
		}
	}
	if len(p.Require) == 0 && len(p.AnyOf) == 1 && len(p.Forbid) == 0 && len(p.AnyOf[0]) == 1 {
		switch p.AnyOf[0][0].Kind {
		case "role":
			return "role"
		case "scope":
			return "scope"
		case "permission":
			return "permission"
		}
	}
	return "custom"
}

// EvalContext 是谓词求值时可用的请求上下文。
type EvalContext struct {
	Operation Operation
	Principal *principal.Principal
	// Request 是 proto.Message（gRPC）或 *http.Request（extra route）。
	Request any
	// Metadata 是请求 metadata/header 的字符串视图。
	Metadata map[string][]string
	// Resource 是可选的对象级授权资源。
	Resource any
}

// Format 返回策略的稳定字符串表示，用于日志、矩阵与 manifest diff。
// preset 元数据保留；requirements/values 会排序。
func Format(p Policy) string {
	var b strings.Builder
	if p.Anonymous {
		b.WriteString("public")
	} else {
		if p.Preset != "" {
			b.WriteString("preset:")
			b.WriteString(p.Preset)
		}
		p.Require = canonicalRequirements(p.Require)
		p.AnyOf = canonicalGroups(p.AnyOf)
		appendReqList(&b, "require", p.Require)
		for i, group := range p.AnyOf {
			if i == 0 {
				b.WriteString(" any_of[")
			} else {
				b.WriteString(" | ")
			}
			appendReqList(&b, "", group)
			if i == len(p.AnyOf)-1 {
				b.WriteString("]")
			}
		}
	}
	appendReqList(&b, "forbid", canonicalRequirements(p.Forbid))
	if b.Len() == 0 {
		return "empty"
	}
	return b.String()
}

func canonicalGroups(groups [][]Requirement) [][]Requirement {
	if len(groups) == 0 {
		return nil
	}
	out := make([][]Requirement, len(groups))
	for i, g := range groups {
		out[i] = canonicalRequirements(g)
	}
	sort.Slice(out, func(i, j int) bool {
		return requirementListKey(out[i]) < requirementListKey(out[j])
	})
	return out
}

func appendReqList(b *strings.Builder, name string, reqs []Requirement) {
	if len(reqs) == 0 {
		return
	}
	if name != "" {
		b.WriteString(" ")
		b.WriteString(name)
		b.WriteString(":")
	}
	for i, r := range reqs {
		if i > 0 {
			b.WriteString(" & ")
		}
		b.WriteString(r.Kind)
		if len(r.Values) > 0 {
			vals := append([]string(nil), r.Values...)
			sort.Strings(vals)
			b.WriteString("(")
			b.WriteString(strings.Join(vals, ","))
			b.WriteString(")")
		}
	}
}

// String 便于调试。
func (o Operation) String() string {
	return fmt.Sprintf("%s[%s,%s,%s]", o.ID, o.Kind, o.Exposure, Format(o.Policy))
}
