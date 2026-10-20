package policy

import (
	"fmt"
	"sort"
)

// ValueSet 是某个词表域允许的值集合。
type ValueSet map[string]struct{}

// Vocabulary 是项目注册的词表：domain -> 允许值。
//
// domain 的约定：普通 kind 用 kind 名；claim kind 用 "claim:<claim名>"。
// 未注册 domain 表示该域自由取值；kind 可以声明 RequiresVocabulary 强制要求。
type Vocabulary map[string]ValueSet

// NewVocabulary 从 domain -> values 构造词表。重复值会去重。
func NewVocabulary(domains map[string][]string) Vocabulary {
	if len(domains) == 0 {
		return nil
	}
	out := make(Vocabulary, len(domains))
	for domain, values := range domains {
		set := make(ValueSet, len(values))
		for _, v := range values {
			set[v] = struct{}{}
		}
		out[domain] = set
	}
	return out
}

// Has 报告 domain 是否注册。
func (v Vocabulary) Has(domain string) bool {
	_, ok := v[domain]
	return ok
}

// Contains 报告 value 是否在 domain 中；domain 未注册时返回 true（自由取值）。
func (v Vocabulary) Contains(domain, value string) bool {
	set, ok := v[domain]
	if !ok {
		return true
	}
	_, ok = set[value]
	return ok
}

// Domain 返回 domain 的排序值列表（用于错误信息/文档）。
func (v Vocabulary) Domain(domain string) []string {
	set := v[domain]
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// validateValues 检查 req 的所有 values 是否在 domain 内。
func (v Vocabulary) validateValues(req Requirement, domain string) error {
	if !v.Has(domain) {
		return nil // 未注册 = 自由取值
	}
	for _, value := range req.Values {
		if !v.Contains(domain, value) {
			return fmt.Errorf("%s value %q is not in vocabulary domain %q", req.Kind, value, domain)
		}
	}
	return nil
}
