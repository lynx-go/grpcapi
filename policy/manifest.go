package policy

import (
	"encoding/json"
	"sort"
)

// Manifest 是策略表的稳定快照，供 CI diff、文档与非 Go 消费者使用。
// 它不是运行时策略源；运行时始终使用 Build 产出的 *Set。
type Manifest struct {
	Version int           `json:"version"`
	APIs    []ManifestAPI `json:"apis"`
}

// ManifestAPI 是单个 API 面的快照。
type ManifestAPI struct {
	Name       string              `json:"name"`
	Operations []ManifestOperation `json:"operations"`
}

// ManifestOperation 是单个 operation 的快照。
type ManifestOperation struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	Exposure   string `json:"exposure"`
	Label      string `json:"label"`
	StreamAuth string `json:"stream_auth,omitempty"`
	Policy     Policy `json:"policy"`
}

// Manifest 返回稳定排序的快照。
func (s *Set) Manifest() Manifest {
	m := Manifest{Version: 1}
	if s == nil {
		return m
	}
	byAPI := make(map[string][]ManifestOperation)
	for _, op := range s.Operations() {
		byAPI[op.API] = append(byAPI[op.API], ManifestOperation{
			ID:         op.ID,
			Kind:       op.Kind.String(),
			Exposure:   op.Exposure.String(),
			Label:      op.EffectiveLabel(),
			StreamAuth: streamAuthString(op),
			Policy:     canonicalPolicy(op.Policy),
		})
	}
	for api, ops := range byAPI {
		sort.Slice(ops, func(i, j int) bool { return ops[i].ID < ops[j].ID })
		m.APIs = append(m.APIs, ManifestAPI{Name: api, Operations: ops})
	}
	sort.Slice(m.APIs, func(i, j int) bool { return m.APIs[i].Name < m.APIs[j].Name })
	return m
}

// JSON 返回缩进 JSON；map key 由 encoding/json 排序，切片已规范化。
func (m Manifest) JSON() ([]byte, error) {
	return json.MarshalIndent(m, "", "  ")
}

func streamAuthString(op Operation) string {
	if !op.Streaming {
		return ""
	}
	return op.StreamAuth.String()
}

// canonicalPolicy 返回用于 diff/format 的规范化副本：清空 preset 元数据，
// values 去重排序，requirements/any_of/forbid 排序。
func canonicalPolicy(p Policy) Policy {
	out := p.Clone()
	out.Preset = ""
	out.PresetArgs = nil
	out.Require = canonicalRequirements(out.Require)
	out.Forbid = canonicalRequirements(out.Forbid)
	out.AnyOf = canonicalGroups(out.AnyOf)
	return out
}

func canonicalRequirements(in []Requirement) []Requirement {
	if len(in) == 0 {
		return nil
	}
	out := make([]Requirement, len(in))
	for i, r := range in {
		r = r.Clone()
		r.Values = canonicalValues(r.Values)
		out[i] = r
	}
	sort.Slice(out, func(i, j int) bool {
		return requirementKey(out[i]) < requirementKey(out[j])
	})
	return out
}

func canonicalValues(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func requirementKey(r Requirement) string {
	key := r.Kind + "\x00" + r.Vocabulary + "\x00" + r.Match.String()
	for _, v := range r.Values {
		key += "\x00" + v
	}
	keys := make([]string, 0, len(r.Params))
	for k := range r.Params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		key += "\x00" + k + "=" + r.Params[k]
	}
	return key
}

func requirementListKey(reqs []Requirement) string {
	key := ""
	for _, r := range reqs {
		key += requirementKey(r) + "\x01"
	}
	return key
}
