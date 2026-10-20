package policy

import "fmt"

// Preset 是项目注册的命名策略宏，在构建期展开为 Policy。
// Preset 不参与运行期求值，只做声明复用。
type Preset struct {
	Name  string
	Build func(args map[string]string) (Policy, error)
}

type presetSet map[string]Preset

func newPresetSet(presets []Preset) (presetSet, error) {
	out := make(presetSet, len(presets))
	for _, p := range presets {
		if p.Name == "" {
			return nil, fmt.Errorf("policy: preset with empty name")
		}
		if p.Build == nil {
			return nil, fmt.Errorf("policy: preset %q has nil Build", p.Name)
		}
		if _, dup := out[p.Name]; dup {
			return nil, fmt.Errorf("policy: preset %q registered twice", p.Name)
		}
		out[p.Name] = p
	}
	return out, nil
}

const maxPresetDepth = 8

// expand 展开 preset，并与内联约束按 AND 合并。
func (ps presetSet) expand(p Policy, stack []string) (Policy, error) {
	if p.Preset == "" {
		return p, nil
	}
	if len(stack) >= maxPresetDepth {
		return Policy{}, fmt.Errorf("policy: preset expansion exceeded depth %d: %v", maxPresetDepth, append(stack, p.Preset))
	}
	for _, name := range stack {
		if name == p.Preset {
			return Policy{}, fmt.Errorf("policy: preset cycle: %v", append(stack, p.Preset))
		}
	}
	base, ok := ps[p.Preset]
	if !ok {
		return Policy{}, fmt.Errorf("policy: unknown preset %q", p.Preset)
	}
	expanded, err := base.Build(cloneStringMap(p.PresetArgs))
	if err != nil {
		return Policy{}, fmt.Errorf("policy: preset %q: %w", p.Preset, err)
	}
	expanded, err = ps.expand(expanded, append(stack, p.Preset))
	if err != nil {
		return Policy{}, err
	}
	return mergePolicy(expanded, p, p.Preset, p.PresetArgs)
}

func mergePolicy(base, inline Policy, preset string, args map[string]string) (Policy, error) {
	inlineHasRequirements := inline.Anonymous || len(inline.Require) > 0 || len(inline.AnyOf) > 0
	if base.Anonymous && inlineHasRequirements {
		return Policy{}, fmt.Errorf("policy: preset %q expands to anonymous and cannot be combined with inline requirements", preset)
	}
	if inline.Anonymous && (len(base.Require) > 0 || len(base.AnyOf) > 0) {
		return Policy{}, fmt.Errorf("policy: anonymous cannot be combined with preset %q requirements", preset)
	}
	out := Policy{
		Preset:     preset,
		PresetArgs: cloneStringMap(args),
		Anonymous:  base.Anonymous || inline.Anonymous,
		Require:    append(append([]Requirement(nil), base.Require...), inline.Require...),
		AnyOf:      append(append([][]Requirement(nil), base.AnyOf...), inline.AnyOf...),
		Forbid:     append(append([]Requirement(nil), base.Forbid...), inline.Forbid...),
	}
	return out, nil
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
