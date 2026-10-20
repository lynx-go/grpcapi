package policy

// Rule 是项目断言钩子：逐 operation 与整表检查，违例聚合进 Build 错误。
type Rule interface {
	Name() string
	CheckOperation(Operation) error
	CheckSet(*Set) error
}

// RuleFunc 便于用函数实现 Rule。
type RuleFunc struct {
	RuleName string
	Method   func(Operation) error
	Set      func(*Set) error
}

func (r RuleFunc) Name() string {
	if r.RuleName == "" {
		return "rule"
	}
	return r.RuleName
}

func (r RuleFunc) CheckOperation(op Operation) error {
	if r.Method == nil {
		return nil
	}
	return r.Method(op)
}

func (r RuleFunc) CheckSet(s *Set) error {
	if r.Set == nil {
		return nil
	}
	return r.Set(s)
}
