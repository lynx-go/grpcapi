package policy

import (
	"context"
	"fmt"
	"sort"
)

// RequirementKind 是可注册的谓词类型。
type RequirementKind struct {
	// Name 是 proto 中 Requirement.kind 的值。
	Name string
	// DefaultMatch 是 Requirement.match 未指定时的默认语义。
	DefaultMatch Match
	// RequiresVocabulary 为 true 时，domain 必须注册词表。
	RequiresVocabulary bool
	// Validate 在构建期校验值域/参数；nil 时使用通用校验。
	Validate func(req Requirement, vocab Vocabulary) error
	// Evaluate 在运行期求值；nil 表示只声明/校验，由自定义 Decider 消费。
	Evaluate func(ctx context.Context, ec EvalContext, req Requirement) (bool, error)
}

// Registry 是 RequirementKind 的不可变注册表（构造后不再修改）。
type Registry struct {
	kinds map[string]RequirementKind
}

// NewRegistry 构造注册表；重复/空 kind 名报错。
func NewRegistry(kinds ...RequirementKind) (*Registry, error) {
	r := &Registry{kinds: make(map[string]RequirementKind, len(kinds))}
	for _, k := range kinds {
		if err := r.Register(k); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// Register 注册一个 kind；Registry 在 Build 前可继续注册，Build 后应视为只读。
func (r *Registry) Register(k RequirementKind) error {
	if k.Name == "" {
		return fmt.Errorf("policy: requirement kind name is empty")
	}
	if _, dup := r.kinds[k.Name]; dup {
		return fmt.Errorf("policy: requirement kind %q registered twice", k.Name)
	}
	r.kinds[k.Name] = k
	return nil
}

// Get 返回 kind。
func (r *Registry) Get(name string) (RequirementKind, bool) {
	if r == nil {
		return RequirementKind{}, false
	}
	k, ok := r.kinds[name]
	return k, ok
}

// Names 返回已注册 kind 名（排序）。
func (r *Registry) Names() []string {
	if r == nil {
		return nil
	}
	out := make([]string, 0, len(r.kinds))
	for name := range r.kinds {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// DefaultRegistry 注册常用约定 kind：
//
//	authenticated
//	claim
//	principal_kind
//	role        -> claims["roles"],       match ANY
//	permission  -> claims["permissions"], match ALL
//	scope       -> claims["scopes"],      match ANY（精确匹配）
//
// resource.op 语义由 policy/scope 预设提供，不在默认 registry 中。
func DefaultRegistry() *Registry {
	r, err := NewRegistry(
		KindAuthenticated(),
		KindClaim(),
		KindPrincipal(),
		ClaimKind("role", "roles", MatchAny),
		ClaimKind("permission", "permissions", MatchAll),
		ClaimKind("scope", "scopes", MatchAny),
	)
	if err != nil {
		panic(err) // 内置 kind 冲突属于编程错误
	}
	return r
}

// KindAuthenticated 匹配任意非 nil Principal。
func KindAuthenticated() RequirementKind {
	return RequirementKind{
		Name:         "authenticated",
		DefaultMatch: MatchAny,
		Validate: func(req Requirement, _ Vocabulary) error {
			if len(req.Values) > 0 || len(req.Params) > 0 {
				return fmt.Errorf("authenticated does not accept values or params")
			}
			return nil
		},
		Evaluate: func(_ context.Context, ec EvalContext, _ Requirement) (bool, error) {
			return ec.Principal != nil, nil
		},
	}
}

// KindClaim 是按 params["name"] 读取 claim 的通用谓词。
// values 为空时表示 claim 存在且非空。
func KindClaim() RequirementKind {
	return RequirementKind{
		Name:         "claim",
		DefaultMatch: MatchAny,
		Validate: func(req Requirement, vocab Vocabulary) error {
			name := req.Params["name"]
			if name == "" {
				return fmt.Errorf("claim requires params.name")
			}
			for key := range req.Params {
				if key != "name" {
					return fmt.Errorf("claim does not accept param %q", key)
				}
			}
			domain := req.Vocabulary
			if domain == "" {
				domain = "claim:" + name
			}
			return vocab.validateValues(req, domain)
		},
		Evaluate: func(_ context.Context, ec EvalContext, req Requirement) (bool, error) {
			name := req.Params["name"]
			if name == "" {
				return false, fmt.Errorf("claim requires params.name")
			}
			switch effectiveMatch(req, MatchAny) {
			case MatchAll:
				return ec.Principal.HasAllClaims(name, req.Values...), nil
			default:
				return ec.Principal.HasClaim(name, req.Values...), nil
			}
		},
	}
}

// KindPrincipal 匹配 Principal.Kind。
func KindPrincipal() RequirementKind {
	return RequirementKind{
		Name:         "principal_kind",
		DefaultMatch: MatchAny,
		Validate: func(req Requirement, vocab Vocabulary) error {
			if len(req.Values) == 0 {
				return fmt.Errorf("principal_kind requires values")
			}
			if len(req.Params) > 0 {
				return fmt.Errorf("principal_kind does not accept params")
			}
			if req.Match == MatchAll && len(req.Values) > 1 {
				return fmt.Errorf("principal_kind is single-valued; MATCH_ALL with multiple values is impossible")
			}
			domain := req.Vocabulary
			if domain == "" {
				domain = "principal_kind"
			}
			return vocab.validateValues(req, domain)
		},
		Evaluate: func(_ context.Context, ec EvalContext, req Requirement) (bool, error) {
			return ec.Principal.HasKind(req.Values...), nil
		},
	}
}

// ClaimKind 构造一个以 kind 名暴露、读取固定 claim 的谓词。
// 例如 ClaimKind("role", "roles", MatchAny)。
func ClaimKind(name, claim string, defaultMatch Match) RequirementKind {
	if defaultMatch == MatchDefault {
		defaultMatch = MatchAny
	}
	return RequirementKind{
		Name:         name,
		DefaultMatch: defaultMatch,
		Validate: func(req Requirement, vocab Vocabulary) error {
			if len(req.Values) == 0 {
				return fmt.Errorf("%s requires at least one value", name)
			}
			if len(req.Params) > 0 {
				return fmt.Errorf("%s does not accept params", name)
			}
			domain := req.Vocabulary
			if domain == "" {
				domain = name
			}
			return vocab.validateValues(req, domain)
		},
		Evaluate: func(_ context.Context, ec EvalContext, req Requirement) (bool, error) {
			switch effectiveMatch(req, defaultMatch) {
			case MatchAll:
				return ec.Principal.HasAllClaims(claim, req.Values...), nil
			default:
				return ec.Principal.HasClaim(claim, req.Values...), nil
			}
		},
	}
}

func effectiveMatch(req Requirement, def Match) Match {
	if req.Match != MatchDefault {
		return req.Match
	}
	if def != MatchDefault {
		return def
	}
	return MatchAny
}
