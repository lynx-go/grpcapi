package guard

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/lynx-go/grpcapi/policy"
	"github.com/lynx-go/grpcapi/surface"
)

// InjectOptions 是 InjectLabels 的配置，字段语义与 MatchOptions 对齐——
// 注入与断言用同一套匹配规则，闭环才不会两边漂移。
type InjectOptions struct {
	// Surface 是 label 来源（必填）。
	Surface *surface.Surface
	// MetadataKey 默认 "x-grpcapi-policy"。
	MetadataKey string
	// Label 默认 operation.EffectiveLabel。
	Label func(policy.Operation) string
	// Pattern 是要注入的文件名 glob；默认 "*.swagger.json"。
	Pattern string
	// Documented 默认 PUBLIC + DEPRECATED（与 AssertDocuments 一致）。
	Documented []policy.Exposure
	// Prefix 是部署前缀；匹配时从文档路径剥离。
	Prefix string
	// NormalizePath 默认 surface.NormalizePath。
	NormalizePath func(string) string
	// Overwrite 控制「文档已有标签且与 Surface 派生不一致」时的行为：
	// false = 报错（fail-closed，暴露生成管线漂移）；true = 覆盖。
	Overwrite bool
	// SkipUnknown 控制「文档 operation 在 Surface 中找不到」时的行为：
	// false = 报错；true = 跳过（预留给手写文档条目）。
	SkipUnknown bool
}

// InjectLabels 把 Surface 派生的 policy label 写入 fs 中 OpenAPI 文档的
// operation 级扩展（默认 x-grpcapi-policy），返回注入后的内存 fs（未命中
// Pattern 的文件原样透传）。
//
// 这是 GENERALIZATION §8.6 的标签注入通道：buf generate 之后、guard 断言
// 之前跑一次（进 CI），文档对账闭环即完整——文档侧标签不再依赖项目自建
// 后处理管线。注意注入会重排 JSON 键序与缩进（map 序列化），比对以
// guard/OpenAPIv2 解析结果为准，不做字节级 diff。
func InjectLabels(src fs.FS, o InjectOptions) (fs.FS, error) {
	if src == nil {
		return nil, fmt.Errorf("guard: InjectLabels src fs.FS is nil")
	}
	if o.Surface == nil {
		return nil, fmt.Errorf("guard: InjectLabels Surface is nil")
	}
	if o.MetadataKey == "" {
		o.MetadataKey = "x-grpcapi-policy"
	}
	if o.Pattern == "" {
		o.Pattern = "*.swagger.json"
	}
	norm := o.NormalizePath
	if norm == nil {
		norm = surface.NormalizePath
	}
	labeler := o.Label
	if labeler == nil {
		labeler = func(op policy.Operation) string { return op.EffectiveLabel() }
	}
	documented := map[policy.Exposure]bool{
		policy.ExposurePublic:     true,
		policy.ExposureDeprecated: true,
	}
	if len(o.Documented) > 0 {
		documented = make(map[policy.Exposure]bool, len(o.Documented))
		for _, e := range o.Documented {
			documented[e] = true
		}
	}

	// 与 AssertDocuments 相同的两级索引：verb+path 与 operationId。
	labels := map[string]string{}
	byOpID := map[string][]string{}
	for _, op := range o.Surface.Operations() {
		if !documented[op.Operation.Exposure] {
			continue
		}
		id := op.Operation.OperationID
		if id == "" {
			id = strings.TrimPrefix(op.Operation.ID, "/")
			id = strings.ReplaceAll(id, "/", "_")
		}
		for _, b := range op.HTTP {
			labels[b.Verb+" "+norm(b.Path)] = labeler(op.Operation)
			byOpID[id] = append(byOpID[id], b.Verb+" "+norm(b.Path))
		}
	}
	if len(labels) == 0 {
		return nil, fmt.Errorf("guard: InjectLabels: Surface 中没有可文档化的 operation")
	}

	out := map[string]*memFile{}
	err := fs.WalkDir(src, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			out[p] = &memFile{mode: fs.ModeDir}
			return nil
		}
		raw, readErr := fs.ReadFile(src, p)
		if readErr != nil {
			return fmt.Errorf("guard: read %s: %w", p, readErr)
		}
		matched, matchErr := path.Match(o.Pattern, d.Name())
		if matchErr != nil {
			return matchErr
		}
		if !matched {
			out[p] = &memFile{data: raw}
			return nil
		}
		injected, injectErr := injectDocument(p, raw, o, labels, byOpID, norm)
		if injectErr != nil {
			return injectErr
		}
		out[p] = &memFile{data: injected}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return memFS(out), nil
}

func injectDocument(p string, raw []byte, o InjectOptions, labels map[string]string, byOpID map[string][]string, norm func(string) string) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("guard: parse %s: %w", p, err)
	}
	paths, _ := doc["paths"].(map[string]any)
	if paths == nil {
		return nil, fmt.Errorf("guard: %s has no paths object", p)
	}
	var names []string
	for pathItem := range paths {
		names = append(names, pathItem)
	}
	sort.Strings(names)
	for _, docPath := range names {
		methods, _ := paths[docPath].(map[string]any)
		if methods == nil {
			continue
		}
		actual := norm(stripPrefix(docPath, o.Prefix, norm))
		var verbs []string
		for m := range methods {
			verbs = append(verbs, m)
		}
		sort.Strings(verbs)
		for _, m := range verbs {
			verb := strings.ToUpper(m)
			switch verb {
			case "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE":
			default:
				continue
			}
			op, _ := methods[m].(map[string]any)
			if op == nil {
				continue
			}
			key := verb + " " + actual
			label, ok := labels[key]
			if !ok {
				if opID, _ := op["operationId"].(string); opID != "" {
					if k, matched := matchByOperationID(opID, byOpID, false); matched {
						label, ok = labels[k]
					}
				}
			}
			if !ok {
				if o.SkipUnknown {
					continue
				}
				return nil, fmt.Errorf("guard: %s: %s %s not found in Surface (set SkipUnknown for handwritten entries)", p, verb, docPath)
			}
			if existing, exists := op[o.MetadataKey]; exists {
				if s, isStr := existing.(string); isStr && s == label {
					continue
				}
				if !o.Overwrite {
					return nil, fmt.Errorf("guard: %s: %s %s already carries %s=%v, Surface says %q (set Overwrite to replace)", p, verb, docPath, o.MetadataKey, existing, label)
				}
			}
			op[o.MetadataKey] = label
		}
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("guard: encode %s: %w", p, err)
	}
	return append(data, '\n'), nil
}

// memFS 是注入结果的最小内存 fs（fs.FS + ReadDirFS），只读。

type memFile struct {
	data []byte
	mode fs.FileMode
}

type memFS map[string]*memFile

func (m memFS) Open(name string) (fs.File, error) {
	f, ok := m[strings.TrimPrefix(name, "./")]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	if f.mode&fs.ModeDir != 0 {
		return &memDir{memEntry: memEntry{name: path.Base(name), file: f}}, nil
	}
	return &memReader{memEntry{name: path.Base(name), file: f}, io.NopCloser(strings.NewReader(string(f.data)))}, nil
}

type memEntry struct {
	name string
	file *memFile
}

func (e memEntry) Name() string { return path.Base(e.name) }
func (e memEntry) IsDir() bool  { return e.file.mode&fs.ModeDir != 0 }
func (e memEntry) Type() fs.FileMode {
	if e.IsDir() {
		return fs.ModeDir
	}
	return 0
}
func (e memEntry) Info() (fs.FileInfo, error) { return e, nil }
func (e memEntry) Size() int64                { return int64(len(e.file.data)) }
func (e memEntry) Mode() fs.FileMode {
	if e.file.mode&fs.ModeDir != 0 {
		return fs.ModeDir | 0o555
	}
	return 0o444
}
func (e memEntry) ModTime() time.Time { return time.Time{} }
func (e memEntry) Sys() any           { return nil }

type memReader struct {
	memEntry
	io.ReadCloser
}

func (r *memReader) Stat() (fs.FileInfo, error) { return r.memEntry, nil }

type memDir struct {
	memEntry
}

func (d *memDir) Stat() (fs.FileInfo, error) { return d.memEntry, nil }
func (d *memDir) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.name, Err: fs.ErrInvalid}
}
func (d *memDir) Close() error { return nil }

func (m memFS) ReadDir(name string) ([]fs.DirEntry, error) {
	name = strings.TrimPrefix(name, "./")
	f, ok := m[name]
	if !ok {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrNotExist}
	}
	if f.mode&fs.ModeDir == 0 {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrInvalid}
	}
	prefix := ""
	if name != "." {
		prefix = name + "/"
	}
	seen := map[string]bool{}
	var out []fs.DirEntry
	for p, mf := range m {
		if p == name || !strings.HasPrefix(p, prefix) {
			continue
		}
		rest := strings.TrimPrefix(p, prefix)
		child := rest
		if i := strings.Index(rest, "/"); i >= 0 {
			child = rest[:i]
		}
		if seen[child] {
			continue
		}
		seen[child] = true
		isDir := strings.Contains(rest, "/") || mf.mode&fs.ModeDir != 0
		mode := fs.ModeDir
		if !isDir {
			mode = 0
		}
		out = append(out, memEntry{name: child, file: &memFile{mode: mode, data: mf.data}})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, nil
}
