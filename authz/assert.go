package authz

import (
	"fmt"
	"strings"
)

// Assertion 是项目断言钩子（可注入规则集）：值域白名单、面前缀、不变量等
// 项目策略经 AssertPolicy（逐方法）与 AssertSet（全集合）注入 Build。两侧
// 均可只关注其一——无检查的一侧返回 nil 即跳过；内嵌 NoopAssertion 可只
// 覆盖关心的一侧。
type Assertion interface {
	// AssertPolicy 对单个方法策略求值；返回非 nil 即违例（聚合进 Build 的错误）。
	AssertPolicy(p MethodPolicy) error
	// AssertSet 对整个集合求值；无集合级检查时返回 nil 即跳过。
	AssertSet(s *PolicySet) error
}

// NoopAssertion 是 Assertion 的空实现基类：项目断言内嵌它后只需覆盖
// AssertPolicy / AssertSet 中关心的一侧。
type NoopAssertion struct{}

// AssertPolicy 空实现：恒通过。
func (NoopAssertion) AssertPolicy(MethodPolicy) error { return nil }

// AssertSet 空实现：恒通过。
func (NoopAssertion) AssertSet(*PolicySet) error { return nil }

// assertSet 求值全部内置断言与项目断言，聚合全部违例为单一 error（全部
// fail-closed，不可关闭）。求值顺序：收集级违例 → 内置逐方法 → 词表断言 →
// 项目断言逐方法 → 项目断言逐集合。
func assertSet(set *PolicySet, opts Options, collectErrs []error) error {
	errs := append([]error(nil), collectErrs...)

	for _, p := range set.Methods() {
		errs = append(errs, assertMethodPolicy(p, opts.AllowStreaming)...)
	}
	errs = append(errs, assertVocabulary(set, opts.Vocabulary)...)

	for _, a := range opts.Assertions {
		if a == nil {
			continue
		}
		for _, p := range set.Methods() {
			if err := a.AssertPolicy(p); err != nil {
				errs = append(errs, fmt.Errorf("assertion %T: method %s: %w", a, p.Method, err))
			}
		}
	}
	for _, a := range opts.Assertions {
		if a == nil {
			continue
		}
		if err := a.AssertSet(set); err != nil {
			errs = append(errs, fmt.Errorf("assertion %T: %w", a, err))
		}
	}

	if len(errs) == 0 {
		return nil
	}
	msgs := make([]string, 0, len(errs))
	for _, err := range errs {
		msgs = append(msgs, err.Error())
	}
	return fmt.Errorf("authz policy assertion failed (fail-closed), %d violation(s):\n  - %s",
		len(errs), strings.Join(msgs, "\n  - "))
}

// assertMethodPolicy 是逐方法的内置断言：
//   - access 未声明（缺注解、服务无缺省档、显式 UNSPECIFIED，含未登记枚举
//     值经收集层归入此类）；
//   - SERVER 面必须声明 api_key_scope；
//   - PERMISSION 面必须声明 permissions；
//   - SYSTEM 档位 v1 禁用；
//   - 流式方法默认拒绝（AllowStreaming 门）。
//
// PUBLIC/END_USER 的值域约束是项目策略，经 Assertion 钩子注入，库不置喙。
func assertMethodPolicy(p MethodPolicy, allowStreaming bool) []error {
	var errs []error
	switch p.Access {
	case AccessUnspecified:
		errs = append(errs, fmt.Errorf("missing auth policy for method %s", p.Method))
	case AccessServer:
		if p.Scope == nil {
			errs = append(errs, fmt.Errorf("method %s: SERVER access must declare api_key_scope (use PERMISSION if not exposed to API keys)", p.Method))
		}
	case AccessPermission:
		if len(p.Permissions) == 0 {
			errs = append(errs, fmt.Errorf("method %s: PERMISSION access must declare permissions", p.Method))
		}
	case AccessSystem:
		errs = append(errs, fmt.Errorf("method %s: ACCESS_LEVEL_SYSTEM is disabled in v1 (see DESIGN.md §9); declare an explicit access level instead", p.Method))
	case AccessPublic, AccessEndUser:
		// 值域主权在项目。
	}
	if p.IsStreaming && !allowStreaming {
		errs = append(errs, fmt.Errorf("method %s: streaming RPC is not supported in v1 (only unary interceptors are wired); set Options.AllowStreaming to opt in", p.Method))
	}
	return errs
}
