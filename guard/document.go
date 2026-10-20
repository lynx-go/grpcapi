package guard

import (
	"context"
	"encoding/json"
)

// Document 是生成式 API 文档的抽象（OpenAPI v2/v3 或其他实现）。
type Document struct {
	Path       string
	Raw        []byte
	TopLevel   map[string]any
	Operations []DocumentOperation
	// Definitions 是 schema 定义（v2 definitions / v3 components.schemas）。
	Definitions map[string]json.RawMessage
}

// DocumentOperation 是文档中的单个 HTTP operation。
type DocumentOperation struct {
	ID                 string
	Verb               string
	Path               string
	Metadata           map[string]any
	DefaultResponseRef string
	Raw                json.RawMessage
}

// Loader 加载文档集合。
type Loader interface {
	Load(ctx context.Context) ([]Document, error)
}

// StringMetadata 返回 metadata 的字符串值；不存在/非字符串返回空串。
func (d Document) StringMetadata(key string) string {
	if d.TopLevel == nil {
		return ""
	}
	s, _ := d.TopLevel[key].(string)
	return s
}

// StringMetadata 返回 operation metadata 的字符串值。
func (o DocumentOperation) StringMetadata(key string) string {
	if o.Metadata == nil {
		return ""
	}
	s, _ := o.Metadata[key].(string)
	return s
}
