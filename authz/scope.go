package authz

import (
	"fmt"
	"strings"
)

// ScopeSet 是 API key 携带的 scope 字符串集合，语言四形态：
//
//	"*"            恒满足任意规则
//	"all"          恒满足任意规则（* 的等价别名）
//	"resource"     精确匹配资源名，任意方向放行
//	"resource.op"  精确匹配资源名与方向（op ∈ read/write/admin）
//
// 实例限定（resource:id）与自定义 scope 是项目层扩展，不进库：本包把携带
// ':' 的 token 按「未知结构」拒绝，fail-closed。
type ScopeSet []string

// ParseScopeSet 解析并校验 scope 集合；任何非法 token（空串、通配符变体、
// 实例限定、未知结构、op 不在 read/write/admin）都报错并逐条指出。解析不
// 涉及项目词表——资源名是否合法由消费点对照 Vocabulary 判定。
func ParseScopeSet(raw []string) (ScopeSet, error) {
	var errs []string
	out := make(ScopeSet, 0, len(raw))
	for _, s := range raw {
		if err := validateScopeToken(s); err != nil {
			errs = append(errs, fmt.Sprintf("scope %q: %v", s, err))
			continue
		}
		out = append(out, s)
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("invalid scope set:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return out, nil
}

// validateScopeToken 校验单个 scope token 的语法（四形态）。
func validateScopeToken(s string) error {
	switch s {
	case "":
		return fmt.Errorf("empty scope")
	case "*", "all":
		return nil
	}
	if strings.Contains(s, "*") {
		return fmt.Errorf("wildcard is only valid as the exact token %q", "*")
	}
	if strings.Contains(s, ":") {
		return fmt.Errorf("instance-scoped scope (resource:id) is not part of the core scope language")
	}
	res, op, hasOp := cutLast(s, ".")
	if !hasOp {
		return nil // resource 形态（空串已由上方分支排除）。
	}
	if res == "" {
		return fmt.Errorf("missing resource before op %q", op)
	}
	if res == "*" || res == "all" {
		return fmt.Errorf("reserved word %q cannot be a resource segment", res)
	}
	if !isRegisteredScopeOp(ScopeOp(op)) {
		return fmt.Errorf("unknown op %q (must be read, write or admin)", op)
	}
	return nil
}

// cutLast 是 strings.Cut 的末次出现变体（op 后缀附着在最后一个 '.' 上，
// 资源名自身允许携带 '.'）。
func cutLast(s, sep string) (before, after string, found bool) {
	if i := strings.LastIndex(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):], true
	}
	return s, "", false
}

// Satisfies 报告集合中是否存在满足规则门（rule）的 scope：
//   - `*` / `all` 恒真；
//   - resource 形态精确匹配资源名即真（任意方向）；
//   - resource.op 形态需同时精确匹配资源名与方向。
//
// 集合中的非法 token（未经验解析手工构造）一律不匹配——fail-closed。
func (ss ScopeSet) Satisfies(rule ScopeRule) bool {
	for _, s := range ss {
		switch s {
		case "*", "all":
			return true
		case "":
			continue
		}
		res, op, hasOp := cutLast(s, ".")
		if !hasOp {
			if res == rule.Resource {
				return true
			}
			continue
		}
		if res == rule.Resource && ScopeOp(op) == rule.Op && isRegisteredScopeOp(ScopeOp(op)) {
			return true
		}
	}
	return false
}
