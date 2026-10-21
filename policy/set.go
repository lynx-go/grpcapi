package policy

import (
	"fmt"
	"sort"
)

// Set 是不可变 operation 策略表。
type Set struct {
	ops      map[string]Operation
	registry *Registry
	vocab    Vocabulary
}

// NewSet 构造空/给定 operation 的集合。重复 ID / 无效策略报错。
// 自定义 RequirementKind 请用 NewSetWithRegistry。
func NewSet(ops ...Operation) (*Set, error) {
	for _, op := range ops {
		if err := ValidateWith(op.Policy, DefaultRegistry(), nil); err != nil {
			return nil, fmt.Errorf("operation %s: %w", op.ID, err)
		}
	}
	return newSet(nil, nil, ops...)
}

// NewSetWithRegistry 使用指定 registry 构造集合（测试/自定义 kind 用）。
// 需要词表校验的 kind 请通过 Build 构造，或使用 NewSetWithVocabulary。
func NewSetWithRegistry(reg *Registry, ops ...Operation) (*Set, error) {
	if reg == nil {
		reg = DefaultRegistry()
	}
	for _, op := range ops {
		if err := ValidateWith(op.Policy, reg, nil); err != nil {
			return nil, fmt.Errorf("operation %s: %w", op.ID, err)
		}
	}
	return newSet(reg, nil, ops...)
}

// NewSetWithVocabulary 使用指定 registry 与词表构造集合。
func NewSetWithVocabulary(reg *Registry, vocab Vocabulary, ops ...Operation) (*Set, error) {
	if reg == nil {
		reg = DefaultRegistry()
	}
	for _, op := range ops {
		if err := ValidateWith(op.Policy, reg, vocab); err != nil {
			return nil, fmt.Errorf("operation %s: %w", op.ID, err)
		}
	}
	return newSet(reg, vocab, ops...)
}

func newSet(reg *Registry, vocab Vocabulary, ops ...Operation) (*Set, error) {
	if reg == nil {
		reg = DefaultRegistry()
	}
	s := &Set{ops: make(map[string]Operation, len(ops)), registry: reg, vocab: vocab}
	for _, op := range ops {
		if op.ID == "" {
			return nil, fmt.Errorf("policy: operation with empty ID")
		}
		if _, dup := s.ops[op.ID]; dup {
			return nil, fmt.Errorf("policy: duplicate operation %q", op.ID)
		}
		s.ops[op.ID] = op.Clone()
	}
	return s, nil
}

// Get 返回 operation 的副本。
func (s *Set) Get(id string) (Operation, bool) {
	if s == nil {
		return Operation{}, false
	}
	op, ok := s.ops[id]
	if !ok {
		return Operation{}, false
	}
	return op.Clone(), true
}

// IsAnonymous 报告 operation 是否显式公开；不存在时返回 false。
func (s *Set) IsAnonymous(id string) bool {
	op, ok := s.Get(id)
	return ok && op.Policy.Anonymous
}

// Operations 返回全部 operation，按 ID 排序。
func (s *Set) Operations() []Operation {
	if s == nil {
		return nil
	}
	out := make([]Operation, 0, len(s.ops))
	for _, op := range s.ops {
		out = append(out, op.Clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// APIs 返回全部 API 面（排序）。
func (s *Set) APIs() []string {
	if s == nil {
		return nil
	}
	seen := make(map[string]struct{})
	for _, op := range s.ops {
		seen[op.API] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for api := range seen {
		out = append(out, api)
	}
	sort.Strings(out)
	return out
}

// FilterAPI 返回只含指定 API 面的新集合；registry 共享。
func (s *Set) FilterAPI(api string) *Set {
	if s == nil {
		return nil
	}
	out := &Set{ops: make(map[string]Operation), registry: s.registry, vocab: s.vocab}
	for id, op := range s.ops {
		if op.API == api {
			out.ops[id] = op.Clone()
		}
	}
	return out
}

// WithOperations 返回合并后的新集合；重复 ID 报错。调用方原集合不被修改。
func (s *Set) WithOperations(ops ...Operation) (*Set, error) {
	if s == nil {
		return NewSet(ops...)
	}
	out := &Set{ops: make(map[string]Operation, len(s.ops)+len(ops)), registry: s.registry, vocab: s.vocab}
	for id, op := range s.ops {
		out.ops[id] = op.Clone()
	}
	for _, op := range ops {
		if err := ValidateWith(op.Policy, out.registry, out.vocab); err != nil {
			return nil, fmt.Errorf("operation %s: %w", op.ID, err)
		}
		if op.ID == "" {
			return nil, fmt.Errorf("policy: operation with empty ID")
		}
		if _, dup := out.ops[op.ID]; dup {
			return nil, fmt.Errorf("policy: duplicate operation %q", op.ID)
		}
		out.ops[op.ID] = op.Clone()
	}
	return out, nil
}

// Registry 返回 Build 时使用的 registry。调用方不得修改。
func (s *Set) Registry() *Registry {
	if s == nil {
		return nil
	}
	return s.registry
}

// Vocabulary 返回 Build 时使用的词表副本。
func (s *Set) Vocabulary() Vocabulary {
	if s == nil {
		return nil
	}
	out := make(Vocabulary, len(s.vocab))
	for domain, values := range s.vocab {
		cp := make(ValueSet, len(values))
		for v := range values {
			cp[v] = struct{}{}
		}
		out[domain] = cp
	}
	return out
}

// Len 返回 operation 数量。
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.ops)
}
