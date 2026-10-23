package guard

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

// NamingRule 判断 JSON 属性名是否合法。
type NamingRule func(string) bool

// SnakeCase 要求 lower_snake_case（允许数字，首字符不能是数字）。
var SnakeCase NamingRule = func(s string) bool {
	if s == "" {
		return true
	}
	for i, ch := range s {
		if ch >= 'A' && ch <= 'Z' {
			return false
		}
		if i == 0 && ch >= '0' && ch <= '9' {
			return false
		}
		if ch != '_' && (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') {
			return false
		}
	}
	return true
}

// CamelCase 要求 lowerCamelCase（允许数字，首字符不能是数字）。
var CamelCase NamingRule = func(s string) bool {
	if s == "" {
		return true
	}
	for i, ch := range s {
		if ch == '_' {
			return false
		}
		if i == 0 {
			if ch < 'a' || ch > 'z' {
				return false
			}
			continue
		}
		isLower := ch >= 'a' && ch <= 'z'
		isUpper := ch >= 'A' && ch <= 'Z'
		isDigit := ch >= '0' && ch <= '9'
		if !isLower && !isUpper && !isDigit {
			return false
		}
	}
	return true
}

// AssertJSONNaming 递归检查文档 schema 的属性名；@type 豁免。
func AssertJSONNaming(t testing.TB, docs []Document, rule NamingRule) {
	t.Helper()
	if len(docs) == 0 {
		t.Fatal("AssertJSONNaming: 文档为空：拒绝空转")
	}
	if rule == nil {
		t.Fatal("AssertJSONNaming: NamingRule 为 nil：拒绝空转")
	}
	var bad []string
	for _, doc := range docs {
		for def, raw := range doc.Definitions {
			walkSchema(raw, func(path string, props map[string]json.RawMessage) {
				for prop := range props {
					if prop == "@type" {
						continue
					}
					if !rule(prop) {
						bad = append(bad, doc.Path+"/"+def+"/"+path+prop)
					}
				}
			})
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		t.Fatalf("AssertJSONNaming: %d property name(s) violate naming rule:\n  - %s", len(bad), strings.Join(bad, "\n  - "))
	}
}

func walkSchema(raw json.RawMessage, visit func(path string, props map[string]json.RawMessage)) {
	var node map[string]json.RawMessage
	if err := json.Unmarshal(raw, &node); err != nil {
		return
	}
	if propsRaw, ok := node["properties"]; ok {
		var props map[string]json.RawMessage
		if err := json.Unmarshal(propsRaw, &props); err == nil {
			visit("", props)
			for name, p := range props {
				walkSchema(p, func(path string, props map[string]json.RawMessage) {
					visit(name+"."+path, props)
				})
			}
		}
	}
	if items, ok := node["items"]; ok {
		walkSchema(items, func(path string, props map[string]json.RawMessage) {
			visit("[]."+path, props)
		})
	}
	if add, ok := node["additionalProperties"]; ok && len(add) > 0 && add[0] == '{' {
		walkSchema(add, func(path string, props map[string]json.RawMessage) {
			visit("additionalProperties."+path, props)
		})
	}
	for _, key := range []string{"allOf", "oneOf", "anyOf"} {
		if arrRaw, ok := node[key]; ok {
			var arr []json.RawMessage
			if err := json.Unmarshal(arrRaw, &arr); err == nil {
				for _, item := range arr {
					walkSchema(item, visit)
				}
			}
		}
	}
}

// AssertNoSchema 断言文档（定义与引用）不含被禁 schema 名。
func AssertNoSchema(t testing.TB, docs []Document, banned string) {
	t.Helper()
	if len(docs) == 0 {
		t.Fatal("AssertNoSchema: 文档为空：拒绝空转")
	}
	if banned == "" {
		t.Fatal("AssertNoSchema: banned 为空：拒绝空转")
	}
	var offenders []string
	for _, doc := range docs {
		if strings.Contains(string(doc.Raw), banned) {
			offenders = append(offenders, doc.Path)
		}
	}
	if len(offenders) > 0 {
		sort.Strings(offenders)
		t.Fatalf("AssertNoSchema: %d document(s) contain banned schema %q:\n  - %s", len(offenders), banned, strings.Join(offenders, "\n  - "))
	}
}
