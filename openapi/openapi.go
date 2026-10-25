// Package openapi 把 surface IR（proto + google.api.http + policy.Set）投影为
// OpenAPI 3.0 文档：路由来自最终部署路径（含 API 组前缀），安全语义来自
// policy——anonymous 方法不带 security，其余标注 bearerAuth；策略谓词以
// x-grpcapi-requirements 扩展原样保留。schema 由 proto 消息描述符递归生成
// （protojson 对齐：字段名用 json_name、枚举取名字、map→additionalProperties、
// 环经 components $ref 断开）。
//
// 消费方：server.Config.OpenAPI 非 nil 时免费挂 GET /openapi.json（见
// server 包）；需要自定义落点的应用可用 Build + Handler 自行组装。
package openapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/lynx-go/grpcapi/policy"
	"github.com/lynx-go/grpcapi/surface"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Info 是文档元信息（server.Config.OpenAPI 的形态；Title 必填）。
type Info struct {
	Title       string `json:"title"`
	Version     string `json:"version,omitempty"`
	Description string `json:"description,omitempty"`
}

// Document 是 OpenAPI 3.0 文档的子集形态（本生态用到的字段）。
type Document struct {
	OpenAPI    string     `json:"openapi"`
	Info       Info       `json:"info"`
	Paths      Paths      `json:"paths"`
	Components Components `json:"components"`
}

// Paths 以最终路径为键；PathItem 以小写 HTTP 方法为键。
type Paths map[string]PathItem

// PathItem 是单个路径下的方法集合（{"get": {...}, "post": {...}}）。
type PathItem map[string]Operation

// Operation 是单个 HTTP operation 的文档投影。
type Operation struct {
	OperationID   string                `json:"operationId,omitempty"`
	Tags          []string              `json:"tags,omitempty"`
	Deprecated    bool                  `json:"deprecated,omitempty"`
	Parameters    []Parameter           `json:"parameters,omitempty"`
	RequestBody   *RequestBody          `json:"requestBody,omitempty"`
	Responses     map[string]Response   `json:"responses"`
	Security      []SecurityRequirement `json:"security"`
	XRequirements []RequirementJSON     `json:"x-grpcapi-requirements,omitempty"`
	XLabel        string                `json:"x-grpcapi-label,omitempty"`
	XSource       string                `json:"x-grpcapi-source,omitempty"`
}

// RequirementJSON 是策略谓词的原样投影（Require/AnyOf/Forbid 平铺）。
type RequirementJSON struct {
	Group      string   `json:"group,omitempty"` // require / any_of / forbid
	Kind       string   `json:"kind"`
	Vocabulary string   `json:"vocabulary,omitempty"`
	Match      string   `json:"match,omitempty"`
	Values     []string `json:"values,omitempty"`
}

// Parameter 是路径/查询参数。
type Parameter struct {
	Name        string  `json:"name"`
	In          string  `json:"in"`
	Required    bool    `json:"required"`
	Description string  `json:"description,omitempty"`
	Schema      *Schema `json:"schema,omitempty"`
}

// RequestBody 是请求体声明。
type RequestBody struct {
	Required bool             `json:"required"`
	Content  map[string]Media `json:"content"`
}

// Response 是单个响应声明。
type Response struct {
	Description string           `json:"description"`
	Content     map[string]Media `json:"content,omitempty"`
}

// Media 是单个 content-type 的载荷声明。
type Media struct {
	Schema *Schema `json:"schema,omitempty"`
}

// SecurityRequirement 是 OpenAPI 安全声明（{"bearerAuth": []} = 需要令牌）。
// 匿名方法用空数组（"security": []）显式声明不需要认证。
type SecurityRequirement map[string][]string

// Components 聚合 schema 与安全方案。
type Components struct {
	Schemas         map[string]*Schema        `json:"schemas,omitempty"`
	SecuritySchemes map[string]SecurityScheme `json:"securitySchemes,omitempty"`
}

// SecurityScheme 声明 Bearer 认证。
type SecurityScheme struct {
	Type         string `json:"type"`
	Scheme       string `json:"scheme"`
	BearerFormat string `json:"bearerFormat,omitempty"`
	Description  string `json:"description,omitempty"`
}

// Schema 是 JSON Schema 的 OpenAPI 3.0 子集。
type Schema struct {
	Ref                  string             `json:"$ref,omitempty"`
	Type                 string             `json:"type,omitempty"`
	Format               string             `json:"format,omitempty"`
	Description          string             `json:"description,omitempty"`
	Items                *Schema            `json:"items,omitempty"`
	Properties           map[string]*Schema `json:"properties,omitempty"`
	AdditionalProperties any                `json:"additionalProperties,omitempty"` // bool 或 *Schema
	Enum                 []string           `json:"enum,omitempty"`
	Nullable             bool               `json:"nullable,omitempty"`
	Deprecated           bool               `json:"deprecated,omitempty"`
}

// Build 从 surface 与最终路由表生成 OpenAPI 文档。
//
// routes 必须是 server 计算后的最终形态（含 API 组前缀；proto 路由带
// ProtoPath，extra 路由 Source=="extra"）。surf 提供操作与消息描述符；
// extraPolicies 以 extra 路由 ID 为键提供策略（server 从 ExtraRoute.Policy
// 聚合，可 nil）——缺失时按需认证保守声明。
func Build(surf *surface.Surface, routes []surface.RouteInfo, info Info, extraPolicies map[string]policy.Policy) (*Document, error) {
	if surf == nil {
		return nil, fmt.Errorf("openapi: surface is nil")
	}
	if info.Title == "" {
		return nil, fmt.Errorf("openapi: Info.Title is required")
	}
	finalPath := make(map[string]string, len(routes))
	for _, r := range routes {
		if r.Source == "proto" {
			finalPath[r.Method+" "+r.ProtoPath] = r.Path
		}
	}
	b := &builder{schemas: map[string]*Schema{}}
	doc := &Document{OpenAPI: "3.0.3", Info: info, Paths: Paths{}}
	for _, op := range surf.Operations() {
		for _, bnd := range op.HTTP {
			path, ok := finalPath[bnd.Verb+" "+bnd.Path]
			if !ok {
				continue
			}
			doc.Paths[path] = appendOperation(doc.Paths[path], strings.ToLower(bnd.Verb),
				b.buildProtoOperation(op, bnd, path))
		}
	}
	for _, r := range routes {
		if r.Source != "extra" {
			continue
		}
		doc.Paths[r.Path] = appendOperation(doc.Paths[r.Path], strings.ToLower(r.Method),
			b.buildExtraOperation(r, extraPolicies))
	}
	doc.Components.Schemas = b.schemas
	doc.Components.SecuritySchemes = map[string]SecurityScheme{
		"bearerAuth": {
			Type:         "http",
			Scheme:       "bearer",
			BearerFormat: "JWT",
			Description:  "Bearer token issued by the application's authenticators (e.g. identity/session modules).",
		},
	}
	return doc, nil
}

func appendOperation(item PathItem, method string, op Operation) PathItem {
	if item == nil {
		item = PathItem{}
	}
	item[method] = op
	return item
}

// JSON 序列化文档（缩进两格，便于 diff 与人工检查）。
func (d *Document) JSON() ([]byte, error) {
	return json.MarshalIndent(d, "", "  ")
}

// Handler 返回静态文档 handler（预序列化；no-store）。
func Handler(doc *Document) (http.Handler, error) {
	if doc == nil {
		return nil, fmt.Errorf("openapi: nil document")
	}
	body, err := doc.JSON()
	if err != nil {
		return nil, fmt.Errorf("openapi: marshal: %w", err)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(body)
	}), nil
}

type builder struct {
	schemas map[string]*Schema
}

func (b *builder) buildProtoOperation(op surface.Operation, bnd surface.HTTPBinding, path string) Operation {
	out := Operation{
		OperationID: operationID(op.Operation),
		Tags:        []string{string(op.Service.Name())},
		Deprecated:  op.Operation.Exposure == policy.ExposureDeprecated,
		XLabel:      op.Operation.EffectiveLabel(),
		XSource:     "proto",
		Responses: map[string]Response{
			"200": {
				Description: "OK",
				Content:     map[string]Media{"application/json": {Schema: b.responseSchema(op, bnd)}},
			},
			"default": {Description: "error (google.rpc.Status with ErrorInfo detail)"},
		},
	}
	applyPolicy(&out, op.Operation.Policy)

	// 路径参数：模板变量逐个定位到请求字段。
	out.Parameters = append(out.Parameters, b.pathParams(path, op.Input)...)
	consumed := consumedByPath(path, op.Input)

	switch {
	case bnd.Body == "*":
		out.RequestBody = &RequestBody{
			Required: true,
			Content:  map[string]Media{"application/json": {Schema: b.messageSchema(op.Input)}},
		}
	case bnd.Body != "":
		out.RequestBody = &RequestBody{
			Required: true,
			Content:  map[string]Media{"application/json": {Schema: b.fieldPathSchema(op.Input, bnd.Body)}},
		}
	default:
		// GET/DELETE：非路径字段按 grpc-gateway 语义映射为查询参数。
		if bnd.Verb == "GET" || bnd.Verb == "DELETE" {
			out.Parameters = append(out.Parameters, queryParams(op.Input, consumed)...)
		}
	}
	return out
}

func (b *builder) buildExtraOperation(r surface.RouteInfo, extraPolicies map[string]policy.Policy) Operation {
	out := Operation{
		OperationID: r.ID,
		XLabel:      r.Label,
		XSource:     "extra",
		Responses: map[string]Response{
			"200":     {Description: "OK"},
			"default": {Description: "error (google.rpc.Status with ErrorInfo detail)"},
		},
	}
	if pol, ok := extraPolicies[r.ID]; ok {
		applyPolicy(&out, pol)
	} else {
		// 策略不可知时保守声明为需认证：宁可文档多要求，不承诺匿名。
		out.Security = []SecurityRequirement{{"bearerAuth": {}}}
	}
	return out
}

func operationID(op policy.Operation) string {
	if op.OperationID != "" {
		return op.OperationID
	}
	return strings.TrimPrefix(op.ID, "/")
}

func applyPolicy(out *Operation, pol policy.Policy) {
	if pol.Anonymous {
		// 显式空数组：不继承全局 security。
		out.Security = []SecurityRequirement{}
	} else {
		out.Security = []SecurityRequirement{{"bearerAuth": {}}}
	}
	for _, r := range pol.Require {
		out.XRequirements = append(out.XRequirements, requirementJSON("require", r))
	}
	for _, group := range pol.AnyOf {
		for _, r := range group {
			out.XRequirements = append(out.XRequirements, requirementJSON("any_of", r))
		}
	}
	for _, r := range pol.Forbid {
		out.XRequirements = append(out.XRequirements, requirementJSON("forbid", r))
	}
}

func requirementJSON(group string, r policy.Requirement) RequirementJSON {
	out := RequirementJSON{Group: group, Kind: r.Kind, Vocabulary: r.Vocabulary}
	if m := r.Match.String(); m != "" && r.Match != policy.MatchDefault {
		out.Match = m
	}
	out.Values = append(out.Values, r.Values...)
	return out
}

// ---- schema 生成 ----

func (b *builder) responseSchema(op surface.Operation, bnd surface.HTTPBinding) *Schema {
	if bnd.ResponseBody == "" {
		return b.messageSchema(op.Output)
	}
	return b.fieldPathSchema(op.Output, bnd.ResponseBody)
}

func (b *builder) messageSchema(md protoreflect.MessageDescriptor) *Schema {
	name := string(md.FullName())
	if _, done := b.schemas[name]; done {
		return refSchema(name)
	}
	if s := wellKnownSchema(md); s != nil {
		b.schemas[name] = s
		return refSchema(name)
	}
	// 占位断环：递归消息先登记再展开。
	b.schemas[name] = &Schema{Type: "object"}
	props := map[string]*Schema{}
	var fieldNames []string
	fields := md.Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		props[fd.JSONName()] = b.fieldSchema(fd)
		fieldNames = append(fieldNames, fd.JSONName())
	}
	sort.Strings(fieldNames)
	ordered := map[string]*Schema{}
	for _, fn := range fieldNames {
		ordered[fn] = props[fn]
	}
	s := &Schema{Type: "object", Properties: ordered}
	if oneofs := md.Oneofs(); oneofs.Len() > 0 {
		var names []string
		for i := 0; i < oneofs.Len(); i++ {
			names = append(names, string(oneofs.Get(i).Name()))
		}
		s.Description = "oneof constraint: " + strings.Join(names, " / ") + " — exactly one member is set (protojson)."
	}
	b.schemas[name] = s
	return refSchema(name)
}

func refSchema(name string) *Schema {
	return &Schema{Ref: "#/components/schemas/" + name}
}

func (b *builder) fieldSchema(fd protoreflect.FieldDescriptor) *Schema {
	if fd.IsMap() {
		return &Schema{
			Type:                 "object",
			AdditionalProperties: b.fieldSchema(fd.MapValue()),
		}
	}
	if fd.IsList() {
		return &Schema{Type: "array", Items: b.singularSchema(fd)}
	}
	return b.singularSchema(fd)
}

func (b *builder) singularSchema(fd protoreflect.FieldDescriptor) *Schema {
	switch fd.Kind() {
	case protoreflect.BoolKind:
		return &Schema{Type: "boolean"}
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return &Schema{Type: "integer", Format: "int32"}
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return &Schema{Type: "integer", Format: "int64"}
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return &Schema{Type: "integer", Format: "int32", Description: "uint32 (protojson emits number)"}
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return &Schema{Type: "integer", Format: "int64", Description: "uint64 (protojson emits number)"}
	case protoreflect.FloatKind:
		return &Schema{Type: "number", Format: "float"}
	case protoreflect.DoubleKind:
		return &Schema{Type: "number", Format: "double"}
	case protoreflect.StringKind:
		return &Schema{Type: "string"}
	case protoreflect.BytesKind:
		return &Schema{Type: "string", Format: "byte"}
	case protoreflect.EnumKind:
		values := enumValueNames(fd.Enum())
		return &Schema{Type: "string", Enum: values}
	case protoreflect.MessageKind, protoreflect.GroupKind:
		return b.messageSchema(fd.Message())
	default:
		return &Schema{Description: "unsupported proto kind " + fd.Kind().String()}
	}
}

func enumValueNames(ed protoreflect.EnumDescriptor) []string {
	values := ed.Values()
	out := make([]string, 0, values.Len())
	for i := 0; i < values.Len(); i++ {
		out = append(out, string(values.Get(i).Name()))
	}
	return out
}

// wellKnownSchema 把 protojson 特殊编码的知名类型映射为标量/容器 schema。
func wellKnownSchema(md protoreflect.MessageDescriptor) *Schema {
	switch md.FullName() {
	case "google.protobuf.Timestamp":
		return &Schema{Type: "string", Format: "date-time"}
	case "google.protobuf.Duration":
		return &Schema{Type: "string", Description: "duration string (e.g. \"30s\")"}
	case "google.protobuf.FieldMask":
		return &Schema{Type: "string"}
	case "google.protobuf.Struct":
		return &Schema{Type: "object", AdditionalProperties: true}
	case "google.protobuf.Value":
		return &Schema{Nullable: true, Description: "any JSON value"}
	case "google.protobuf.ListValue":
		return &Schema{Type: "array", Items: &Schema{Nullable: true, Description: "any JSON value"}}
	case "google.protobuf.StringValue":
		return &Schema{Type: "string", Nullable: true}
	case "google.protobuf.NumberValue":
		return &Schema{Type: "number", Nullable: true}
	case "google.protobuf.BoolValue":
		return &Schema{Type: "boolean", Nullable: true}
	case "google.protobuf.Int32Value":
		return &Schema{Type: "integer", Format: "int32", Nullable: true}
	case "google.protobuf.Int64Value":
		return &Schema{Type: "integer", Format: "int64", Nullable: true}
	case "google.protobuf.UInt32Value":
		return &Schema{Type: "integer", Format: "int32", Nullable: true}
	case "google.protobuf.UInt64Value":
		return &Schema{Type: "integer", Format: "int64", Nullable: true}
	case "google.protobuf.FloatValue":
		return &Schema{Type: "number", Format: "float", Nullable: true}
	case "google.protobuf.DoubleValue":
		return &Schema{Type: "number", Format: "double", Nullable: true}
	case "google.protobuf.BytesValue":
		return &Schema{Type: "string", Format: "byte", Nullable: true}
	case "google.protobuf.Empty":
		return &Schema{Type: "object"}
	case "google.protobuf.Any":
		return &Schema{Type: "object"}
	default:
		return nil
	}
}

// ---- 参数生成 ----

// pathVars 抽取路径模板变量（{id} / {payload.id}）。
func pathVars(path string) []string {
	var out []string
	for _, seg := range strings.Split(path, "/") {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			out = append(out, strings.Trim(seg, "{}"))
		}
	}
	return out
}

func (b *builder) pathParams(path string, input protoreflect.MessageDescriptor) []Parameter {
	var out []Parameter
	for _, v := range pathVars(path) {
		schema := b.fieldPathSchema(input, v)
		if schema == nil {
			schema = &Schema{Type: "string"}
		}
		out = append(out, Parameter{
			Name:     v,
			In:       "path",
			Required: true,
			Schema:   schema,
		})
	}
	return out
}

func consumedByPath(path string, input protoreflect.MessageDescriptor) map[string]bool {
	consumed := map[string]bool{}
	for _, v := range pathVars(path) {
		consumed[strings.SplitN(v, ".", 2)[0]] = true
	}
	return consumed
}

func queryParams(input protoreflect.MessageDescriptor, consumed map[string]bool) []Parameter {
	var out []Parameter
	fields := input.Fields()
	names := make([]string, 0, fields.Len())
	byName := map[string]protoreflect.FieldDescriptor{}
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		n := string(fd.Name())
		names = append(names, n)
		byName[n] = fd
	}
	sort.Strings(names)
	for _, n := range names {
		if consumed[n] {
			continue
		}
		fd := byName[n]
		p := Parameter{Name: n, In: "query"}
		switch {
		case fd.IsMap():
			p.Description = "map filter (grpc-gateway query params)"
			p.Schema = &Schema{Type: "string"}
		case fd.IsList():
			p.Schema = &Schema{Type: "array", Items: queryItemSchema(fd)}
		case fd.Kind() == protoreflect.MessageKind || fd.Kind() == protoreflect.GroupKind:
			p.Description = "nested filter, dot-separated (e.g. " + n + ".sub)"
			p.Schema = &Schema{Type: "string"}
		default:
			p.Schema = queryItemSchema(fd)
		}
		out = append(out, p)
	}
	return out
}

func queryItemSchema(fd protoreflect.FieldDescriptor) *Schema {
	switch fd.Kind() {
	case protoreflect.BoolKind:
		return &Schema{Type: "boolean"}
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind,
		protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind,
		protoreflect.Uint32Kind, protoreflect.Fixed32Kind,
		protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return &Schema{Type: "integer"}
	case protoreflect.FloatKind, protoreflect.DoubleKind:
		return &Schema{Type: "number"}
	case protoreflect.EnumKind:
		return &Schema{Type: "string"}
	default:
		return &Schema{Type: "string"}
	}
}

// fieldPathSchema 沿点分字段路径定位子 schema（"payload.id"）。
func (b *builder) fieldPathSchema(input protoreflect.MessageDescriptor, fieldPath string) *Schema {
	md := input
	var last protoreflect.FieldDescriptor
	for _, seg := range strings.Split(fieldPath, ".") {
		if md == nil {
			return nil
		}
		fd := fieldByProtoName(md, seg)
		if fd == nil {
			return nil
		}
		last = fd
		if fd.Kind() == protoreflect.MessageKind || fd.Kind() == protoreflect.GroupKind {
			md = fd.Message()
		} else {
			md = nil
		}
	}
	if last == nil {
		return nil
	}
	return b.fieldSchema(last)
}

// fieldByProtoName 按 proto 字段名（非 json_name）查找——路径模板与 body
// 选择器写的是 proto 名。
func fieldByProtoName(md protoreflect.MessageDescriptor, name string) protoreflect.FieldDescriptor {
	fields := md.Fields()
	for i := 0; i < fields.Len(); i++ {
		if string(fields.Get(i).Name()) == name {
			return fields.Get(i)
		}
	}
	return nil
}
