package guard

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// OpenAPIv2Options 是 OpenAPI v2 loader 配置。
type OpenAPIv2Options struct {
	// Pattern 默认 "*.swagger.json"。
	Pattern string
	// Include 可选过滤（相对 fs 的路径）。
	Include func(string) bool
	// MaxDocuments 可选上限；超出报错。
	MaxDocuments int
}

// OpenAPIv3Options 是 OpenAPI v3 loader 配置。
type OpenAPIv3Options struct {
	// Pattern 默认 "*.openapi.json"。
	Pattern      string
	Include      func(string) bool
	MaxDocuments int
}

type v2Document struct {
	Paths       map[string]map[string]json.RawMessage `json:"paths"`
	Definitions map[string]json.RawMessage            `json:"definitions"`
}

type v3Document struct {
	Paths      map[string]map[string]json.RawMessage `json:"paths"`
	Components struct {
		Schemas map[string]json.RawMessage `json:"schemas"`
	} `json:"components"`
}

type v2Operation struct {
	OperationID string `json:"operationId"`
	Responses   struct {
		Default struct {
			Schema struct {
				Ref string `json:"$ref"`
			} `json:"schema"`
		} `json:"default"`
	} `json:"responses"`
}

type v3Operation struct {
	OperationID string `json:"operationId"`
	Responses   struct {
		Default struct {
			Ref     string `json:"$ref"`
			Content map[string]struct {
				Schema struct {
					Ref string `json:"$ref"`
				} `json:"schema"`
			} `json:"content"`
		} `json:"default"`
	} `json:"responses"`
}

// OpenAPIv2 返回扫描 fs.FS 中 OpenAPI v2 文档的 loader。
func OpenAPIv2(fsys fs.FS, opts OpenAPIv2Options) (Loader, error) {
	if fsys == nil {
		return nil, fmt.Errorf("guard: OpenAPIv2 fs.FS is nil")
	}
	if opts.Pattern == "" {
		opts.Pattern = "*.swagger.json"
	}
	return &fsLoader{fsys: fsys, pattern: opts.Pattern, include: opts.Include, max: opts.MaxDocuments, version: 2}, nil
}

// OpenAPIv3 返回扫描 fs.FS 中 OpenAPI v3 文档的 loader。
func OpenAPIv3(fsys fs.FS, opts OpenAPIv3Options) (Loader, error) {
	if fsys == nil {
		return nil, fmt.Errorf("guard: OpenAPIv3 fs.FS is nil")
	}
	if opts.Pattern == "" {
		opts.Pattern = "*.openapi.json"
	}
	return &fsLoader{fsys: fsys, pattern: opts.Pattern, include: opts.Include, max: opts.MaxDocuments, version: 3}, nil
}

type fsLoader struct {
	fsys    fs.FS
	pattern string
	include func(string) bool
	max     int
	version int
}

func (l *fsLoader) Load(ctx context.Context) ([]Document, error) {
	var docs []Document
	err := fs.WalkDir(l.fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if l.include != nil && !l.include(p) {
			return nil
		}
		ok, err := path.Match(l.pattern, d.Name())
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		raw, err := fs.ReadFile(l.fsys, p)
		if err != nil {
			return fmt.Errorf("guard: read %s: %w", p, err)
		}
		doc, err := parseDocument(p, raw, l.version)
		if err != nil {
			return err
		}
		docs = append(docs, doc)
		if l.max > 0 && len(docs) > l.max {
			return fmt.Errorf("guard: more than %d documents matched %q", l.max, l.pattern)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(docs, func(i, j int) bool { return docs[i].Path < docs[j].Path })
	return docs, nil
}

func parseDocument(p string, raw []byte, version int) (Document, error) {
	doc := Document{Path: p, Raw: raw}
	switch version {
	case 2:
		var v2 v2Document
		if err := json.Unmarshal(raw, &v2); err != nil {
			return Document{}, fmt.Errorf("guard: parse %s: %w", p, err)
		}
		doc.Definitions = v2.Definitions
		ops, err := parseOps(v2.Paths, func(rawOp json.RawMessage) (string, string, map[string]any, error) {
			var op v2Operation
			if err := json.Unmarshal(rawOp, &op); err != nil {
				return "", "", nil, err
			}
			md, err := opMetadata(rawOp)
			if err != nil {
				return "", "", nil, err
			}
			return op.OperationID, op.Responses.Default.Schema.Ref, md, nil
		})
		if err != nil {
			return Document{}, fmt.Errorf("guard: parse %s: %w", p, err)
		}
		doc.Operations = ops
	case 3:
		var v3 v3Document
		if err := json.Unmarshal(raw, &v3); err != nil {
			return Document{}, fmt.Errorf("guard: parse %s: %w", p, err)
		}
		doc.Definitions = v3.Components.Schemas
		ops, err := parseOps(v3.Paths, func(rawOp json.RawMessage) (string, string, map[string]any, error) {
			var op v3Operation
			if err := json.Unmarshal(rawOp, &op); err != nil {
				return "", "", nil, err
			}
			ref := op.Responses.Default.Ref
			if ref == "" {
				keys := make([]string, 0, len(op.Responses.Default.Content))
				for k := range op.Responses.Default.Content {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					if r := op.Responses.Default.Content[k].Schema.Ref; r != "" {
						ref = r
						break
					}
				}
			}
			md, err := opMetadata(rawOp)
			if err != nil {
				return "", "", nil, err
			}
			return op.OperationID, ref, md, nil
		})
		if err != nil {
			return Document{}, fmt.Errorf("guard: parse %s: %w", p, err)
		}
		doc.Operations = ops
	default:
		return Document{}, fmt.Errorf("guard: unsupported OpenAPI version %d", version)
	}
	top, err := topMetadata(raw)
	if err != nil {
		return Document{}, fmt.Errorf("guard: parse %s metadata: %w", p, err)
	}
	doc.TopLevel = top
	return doc, nil
}

type opParse func(json.RawMessage) (id, responseRef string, metadata map[string]any, err error)

func parseOps(paths map[string]map[string]json.RawMessage, parse opParse) ([]DocumentOperation, error) {
	var out []DocumentOperation
	for p, methods := range paths {
		for method, raw := range methods {
			verb := strings.ToUpper(method)
			switch verb {
			case "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE":
			default:
				continue
			}
			id, ref, meta, err := parse(raw)
			if err != nil {
				return nil, fmt.Errorf("%s %s: %w", verb, p, err)
			}
			out = append(out, DocumentOperation{
				ID: id, Verb: verb, Path: p, Metadata: meta,
				DefaultResponseRef: ref, Raw: raw,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Verb < out[j].Verb
	})
	return out, nil
}

func topMetadata(raw []byte) (map[string]any, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return extensionMap(m)
}

func opMetadata(raw json.RawMessage) (map[string]any, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return extensionMap(m)
}

func extensionMap(m map[string]json.RawMessage) (map[string]any, error) {
	out := make(map[string]any)
	for k, v := range m {
		if !strings.HasPrefix(strings.ToLower(k), "x-") {
			continue
		}
		var value any
		if err := json.Unmarshal(v, &value); err != nil {
			return nil, fmt.Errorf("extension %s: %w", k, err)
		}
		out[k] = value
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}
