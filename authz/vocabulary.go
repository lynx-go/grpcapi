package authz

import (
	"fmt"
	"sort"
)

// Vocabulary 是项目注册的 scope 资源词表（词表主权：值域因项目而异，库只
// 提供「注册词表 + fail-closed 校验」框架，见 DESIGN.md §2）。存在任何
// api_key_scope 声明而词表为空，Build 构造失败——杜绝 fail-open 窗口。
type Vocabulary struct {
	ScopeResources []string
}

// Vocabulary 从全部方法的 Scope 声明派生被引用的资源词表（字典序、去重）。
// 与注册词表 Vocabulary 不同：这是 PolicySet 的投影，供 scope 下发与生成
// 消费——死 scope 断言保证词表内每个资源至少被引用一次。
func (s *PolicySet) Vocabulary() []string {
	if s == nil {
		return nil
	}
	seen := make(map[string]struct{})
	out := make([]string, 0)
	for _, p := range s.Methods() {
		if p.Scope == nil {
			continue
		}
		if _, dup := seen[p.Scope.Resource]; dup {
			continue
		}
		seen[p.Scope.Resource] = struct{}{}
		out = append(out, p.Scope.Resource)
	}
	sort.Strings(out)
	return out
}

// assertVocabulary 是词表相关的内置断言（不可关闭）：
//   - 词表为空且存在 scope 声明 → 构造失败（fail-open 防线，并跳过后续
//     scope 检查——空词表下逐条检查只会产生噪音）；
//   - 每个 scope 的资源必须在词表内（逐条指出）；
//   - 每个 scope 的方向必须是已登记值；
//   - 死 scope：词表内资源必须被至少一个方法引用（在全部方法收集完后
//     对整表检查；词表为空且无 scope 声明则整体跳过）。
func assertVocabulary(set *PolicySet, vocab Vocabulary) []error {
	referenced := make(map[string]struct{})
	firstScopeMethod := ""
	for _, p := range set.Methods() {
		if p.Scope == nil {
			continue
		}
		if firstScopeMethod == "" {
			firstScopeMethod = p.Method
		}
		referenced[p.Scope.Resource] = struct{}{}
	}

	if len(vocab.ScopeResources) == 0 {
		if len(referenced) > 0 {
			return []error{fmt.Errorf("vocabulary is empty but methods declare api_key_scope (first: %s); register opts.Vocabulary.ScopeResources to guard against fail-open", firstScopeMethod)}
		}
		return nil
	}

	var errs []error
	vocabSet := make(map[string]struct{}, len(vocab.ScopeResources))
	for _, r := range vocab.ScopeResources {
		vocabSet[r] = struct{}{}
	}
	for _, p := range set.Methods() {
		if p.Scope == nil {
			continue
		}
		if _, ok := vocabSet[p.Scope.Resource]; !ok {
			errs = append(errs, fmt.Errorf("method %s: scope resource %q is not in the vocabulary", p.Method, p.Scope.Resource))
		}
		if !isRegisteredScopeOp(p.Scope.Op) {
			errs = append(errs, fmt.Errorf("method %s: scope op %q is not registered (must be read, write or admin)", p.Method, string(p.Scope.Op)))
		}
	}

	ordered := append([]string(nil), vocab.ScopeResources...)
	sort.Strings(ordered)
	for _, r := range ordered {
		if _, ok := referenced[r]; !ok {
			errs = append(errs, fmt.Errorf("dead scope: resource %q is in the vocabulary but not referenced by any method (leftover from vocabulary evolution)", r))
		}
	}
	return errs
}
