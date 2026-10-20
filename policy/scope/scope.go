// Package scope 提供 resource / resource.op 形式的 API key scope 预设。
//
// 核心 policy 包只做精确 claim 匹配；本包把 scope 语言解析、词表校验与
// 匹配语义做成可注册的 RequirementKind。项目不使用这种 scope 语言时
// 不需要 import 本包。
package scope

import (
	"context"
	"fmt"
	"strings"

	"github.com/lynx-go/grpcapi/policy"
)

// Options 是 scope kind 的配置。
type Options struct {
	// Claim 是 Principal 中承载 scope 的 claim 名；默认 "scopes"。
	Claim string
	// VocabularyDomain 是资源词表域；默认 "scope"。
	VocabularyDomain string
	// RequireVocabulary 为 true 时，声明 scope 必须注册资源词表。
	RequireVocabulary bool
	// DisallowWildcard 为 true 时拒绝 "*" / "all"。
	DisallowWildcard bool
}

func (o Options) claim() string {
	if o.Claim == "" {
		return "scopes"
	}
	return o.Claim
}

func (o Options) domain() string {
	if o.VocabularyDomain == "" {
		return "scope"
	}
	return o.VocabularyDomain
}

// Kind 构造名为 "scope" 的 RequirementKind。
func Kind(opts Options) policy.RequirementKind {
	return policy.RequirementKind{
		Name:               "scope",
		DefaultMatch:       policy.MatchAny,
		RequiresVocabulary: opts.RequireVocabulary,
		Validate: func(req policy.Requirement, vocab policy.Vocabulary) error {
			if req.Match == policy.MatchAll && len(req.Values) == 0 {
				return fmt.Errorf("scope MATCH_ALL requires values")
			}
			domain := req.Vocabulary
			if domain == "" {
				domain = opts.domain()
			}
			if opts.RequireVocabulary && !vocab.Has(domain) {
				return fmt.Errorf("scope requires vocabulary domain %q, but it is not registered", domain)
			}
			for _, value := range req.Values {
				if value == "*" || value == "all" {
					if opts.DisallowWildcard {
						return fmt.Errorf("scope wildcard %q is disabled", value)
					}
					continue
				}
				resource, _, err := parse(value)
				if err != nil {
					return err
				}
				if vocab.Has(domain) && !vocab.Contains(domain, resource) {
					return fmt.Errorf("scope resource %q is not in vocabulary domain %q", resource, domain)
				}
			}
			return nil
		},
		Evaluate: func(_ context.Context, ec policy.EvalContext, req policy.Requirement) (bool, error) {
			if ec.Principal == nil {
				return false, nil
			}
			set := Set(ec.Principal.Claim(opts.claim()))
			all := req.Match == policy.MatchAll
			for _, want := range req.Values {
				var ok bool
				if want == "*" || want == "all" {
					ok = !opts.DisallowWildcard
				} else {
					resource, op, err := parse(want)
					if err != nil {
						return false, err
					}
					ok = set.satisfies(resource, op, !opts.DisallowWildcard)
				}
				if all && !ok {
					return false, nil
				}
				if !all && ok {
					return true, nil
				}
			}
			return all, nil
		},
	}
}

// Set 是 Principal 携带的 scope token 集合。
type Set []string

// Parse 解析并校验 scope 集合；非法 token 逐条报错。
func Parse(raw []string) (Set, error) {
	out := make(Set, 0, len(raw))
	var errs []string
	for _, token := range raw {
		if token == "*" || token == "all" {
			out = append(out, token)
			continue
		}
		if _, _, err := parse(token); err != nil {
			errs = append(errs, fmt.Sprintf("scope %q: %v", token, err))
			continue
		}
		out = append(out, token)
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("invalid scope set:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return out, nil
}

// Satisfies 报告集合是否允许 resource/op；op 为空表示只要求资源。
// 通配符按放行处理；需要严格模式用 satisfies(..., false)。
func (s Set) Satisfies(resource, op string) bool {
	return s.satisfies(resource, op, true)
}

func (s Set) satisfies(resource, op string, allowWildcard bool) bool {
	for _, token := range s {
		if token == "*" || token == "all" {
			if allowWildcard {
				return true
			}
			continue
		}
		res, tokenOp, hasOp := splitToken(token)
		if res != resource {
			continue
		}
		if !hasOp {
			// principal 的 resource 形式表示该资源任意方向。
			return true
		}
		if op == "" || tokenOp == op {
			return true
		}
	}
	return false
}

// parse 解析 "resource" 或 "resource:op"。
//
// 规范形态用冒号（notes:write）；为兼容 v2/torchwood 的 resource.op 形态，
// 当点号后缀是已知 op 时也接受 notes.write。资源名本身允许包含点号。
func parse(token string) (resource, op string, err error) {
	switch token {
	case "":
		return "", "", fmt.Errorf("empty scope")
	case "*", "all":
		return "", "", nil
	}
	if strings.Contains(token, "*") {
		return "", "", fmt.Errorf("wildcard is only valid as the exact token %q", "*")
	}
	res, tokenOp, hasOp := splitToken(token)
	if !hasOp {
		return res, "", nil
	}
	if res == "" {
		return "", "", fmt.Errorf("missing resource before op %q", tokenOp)
	}
	if res == "*" || res == "all" {
		return "", "", fmt.Errorf("reserved word %q cannot be a resource segment", res)
	}
	if !isOp(tokenOp) {
		return "", "", fmt.Errorf("unknown op %q (must be read, write or admin)", tokenOp)
	}
	return res, tokenOp, nil
}

// splitToken 优先按冒号切分；没有冒号时，仅当点号后缀是已知 op 才切分。
func splitToken(token string) (resource, op string, hasOp bool) {
	if res, op, ok := cutLast(token, ":"); ok {
		return res, op, true
	}
	if res, op, ok := cutLast(token, "."); ok && isOp(op) && res != "" {
		return res, op, true
	}
	return token, "", false
}

func isOp(op string) bool {
	switch op {
	case "read", "write", "admin":
		return true
	default:
		return false
	}
}

func cutLast(s, sep string) (before, after string, found bool) {
	if i := strings.LastIndex(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):], true
	}
	return s, "", false
}
