package guard

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/lynx-go/grpcapi/policy"
	"github.com/lynx-go/grpcapi/surface"
)

// MatchOptions 是 AssertDocuments 的配置。
type MatchOptions struct {
	// MetadataKey 默认 "x-grpcapi-policy"。
	MetadataKey string
	// SkipMetadata 默认 false：文档缺扩展即失败。
	SkipMetadata bool
	// Label 默认 operation.EffectiveLabel。
	Label func(policy.Operation) string
	// Documented 默认 PUBLIC + DEPRECATED。
	Documented []policy.Exposure
	// Ignore 可跳过非 API operation（如健康检查/文档页）。
	Ignore func(DocumentOperation) bool
	// ErrorRef 可选：校验 default 响应引用。
	ErrorRef func(Document, DocumentOperation) (string, bool)
	// Prefix 是部署前缀；匹配时从文档路径剥离。
	Prefix string
	// NormalizePath 默认 surface.NormalizePath。
	NormalizePath func(string) string
	// DisableOperationIDFallback 默认 false。
	DisableOperationIDFallback bool
	// CheckTopLevel 需要 ServiceLabel。
	CheckTopLevel bool
	// ServiceLabel 返回服务默认文档 label。
	ServiceLabel  func(service string) (string, bool)
	MinDocuments  int
	MinOperations int
}

type expectedOp struct {
	op      surface.Operation
	binding surface.HTTPBinding
}

// AssertDocuments 断言 OpenAPI 文档与 surface 的策略/路由一致。
func AssertDocuments(t testing.TB, loader Loader, surf *surface.Surface, o MatchOptions) {
	t.Helper()
	if loader == nil {
		t.Fatal("AssertDocuments: Loader 为 nil：拒绝空转")
	}
	if surf == nil {
		t.Fatal("AssertDocuments: Surface 为 nil：拒绝空转")
	}
	norm := o.NormalizePath
	if norm == nil {
		norm = surface.NormalizePath
	}
	labeler := o.Label
	if labeler == nil {
		labeler = func(op policy.Operation) string { return op.EffectiveLabel() }
	}
	key := o.MetadataKey
	if key == "" {
		key = "x-grpcapi-policy"
	}
	documented := make(map[policy.Exposure]bool)
	if len(o.Documented) == 0 {
		documented[policy.ExposurePublic] = true
		documented[policy.ExposureDeprecated] = true
	} else {
		for _, e := range o.Documented {
			documented[e] = true
		}
	}

	expected := make(map[string]expectedOp)
	byOpID := make(map[string][]string)
	for _, op := range surf.Operations() {
		if !documented[op.Operation.Exposure] {
			continue
		}
		for _, b := range op.HTTP {
			k := b.Verb + " " + norm(b.Path)
			expected[k] = expectedOp{op: op, binding: b}
			id := op.Operation.OperationID
			if id == "" {
				id = strings.TrimPrefix(op.Operation.ID, "/")
				id = strings.ReplaceAll(id, "/", "_")
			}
			byOpID[id] = append(byOpID[id], k)
		}
	}
	if len(expected) == 0 {
		t.Fatal("AssertDocuments: Surface 中没有可文档化的 operation：拒绝空转")
	}

	docs, err := loader.Load(context.Background())
	if err != nil {
		t.Fatalf("AssertDocuments: Load: %v", err)
	}
	if len(docs) == 0 {
		t.Fatal("AssertDocuments: 未加载到任何文档：拒绝空转")
	}
	if o.MinDocuments > 0 && len(docs) < o.MinDocuments {
		t.Fatalf("AssertDocuments: 文档数 %d 低于下限 %d", len(docs), o.MinDocuments)
	}

	seen := make(map[string]int)
	checked := 0
	var failures []string
	for _, doc := range docs {
		services := make(map[string]struct{})
		for _, op := range doc.Operations {
			verbPath := op.Verb + " " + norm(stripPrefix(op.Path, o.Prefix, norm))
			exp, ok := expected[verbPath]
			if !ok {
				if k, matched := matchByOperationID(op.ID, byOpID, o.DisableOperationIDFallback); matched {
					verbPath, exp, ok = k, expected[k], true
				}
			}
			if !ok {
				if o.Ignore != nil && o.Ignore(op) {
					continue
				}
				failures = append(failures, fmt.Sprintf("%s: %s %s not in surface", doc.Path, op.Verb, op.Path))
				continue
			}
			if !o.SkipMetadata {
				actual := op.StringMetadata(key)
				if actual == "" {
					actual = doc.StringMetadata(key)
				}
				if actual == "" {
					failures = append(failures, fmt.Sprintf("%s: %s %s missing metadata %q", doc.Path, op.Verb, op.Path, key))
				} else if want := labeler(exp.op.Operation); actual != want {
					failures = append(failures, fmt.Sprintf("%s: %s %s metadata %q = %q, want %q", doc.Path, op.Verb, op.Path, key, actual, want))
				}
			}
			if o.ErrorRef != nil {
				if want, ok := o.ErrorRef(doc, op); ok && want != "" && op.DefaultResponseRef != want {
					failures = append(failures, fmt.Sprintf("%s: %s %s default ref = %q, want %q", doc.Path, op.Verb, op.Path, op.DefaultResponseRef, want))
				}
			}
			seen[verbPath]++
			checked++
			services[exp.op.Operation.Service] = struct{}{}
		}
		if o.CheckTopLevel && o.ServiceLabel != nil && len(services) == 1 {
			var svc string
			for s := range services {
				svc = s
			}
			want, ok := o.ServiceLabel(svc)
			if ok && want != "" {
				actual := doc.StringMetadata(key)
				if actual != want {
					failures = append(failures, fmt.Sprintf("%s: top-level metadata %q = %q, want %q", doc.Path, key, actual, want))
				}
			}
		}
	}

	if o.MinOperations > 0 && checked < o.MinOperations {
		failures = append(failures, fmt.Sprintf("checked operations %d < min %d", checked, o.MinOperations))
	}
	var missing []string
	for k := range expected {
		if seen[k] == 0 {
			missing = append(missing, k)
		}
	}
	sort.Strings(missing)
	for _, k := range missing {
		failures = append(failures, fmt.Sprintf("surface operation missing from documents: %s", k))
	}
	if len(failures) > 0 {
		sort.Strings(failures)
		t.Fatalf("AssertDocuments: %d violation(s):\n  - %s", len(failures), strings.Join(failures, "\n  - "))
	}
}

func stripPrefix(path, prefix string, norm func(string) string) string {
	if prefix == "" {
		return path
	}
	prefix = norm(prefix)
	path = norm(path)
	if path == prefix {
		return "/"
	}
	if strings.HasPrefix(path, prefix+"/") {
		return strings.TrimPrefix(path, prefix)
	}
	return path
}

func matchByOperationID(id string, byOpID map[string][]string, disabled bool) (string, bool) {
	if disabled || id == "" {
		return "", false
	}
	if keys := byOpID[id]; len(keys) == 1 {
		return keys[0], true
	}
	base := strings.TrimRight(id, "0123456789")
	if base != id {
		if keys := byOpID[base]; len(keys) == 1 {
			return keys[0], true
		}
	}
	return "", false
}
