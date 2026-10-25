package openapi_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	echov1 "github.com/lynx-go/grpcapi/example/echo/v1"
	"github.com/lynx-go/grpcapi/openapi"
	"github.com/lynx-go/grpcapi/policy"
	"github.com/lynx-go/grpcapi/policy/protopolicy"
	"github.com/lynx-go/grpcapi/surface"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func exampleDoc(t *testing.T) *openapi.Document {
	t.Helper()
	set, err := policy.Build(context.Background(), policy.FromFiles(echov1.File_echo_proto), policy.Options{
		Provider: protopolicy.New(protopolicy.Options{}),
		Registry: policy.DefaultRegistry(),
	})
	if err != nil {
		t.Fatalf("policy.Build: %v", err)
	}
	s, err := surface.Build([]protoreflect.FileDescriptor{echov1.File_echo_proto}, set)
	if err != nil {
		t.Fatalf("surface.Build: %v", err)
	}
	// 模拟 server 的最终路由：public API 无前缀时 finalPath == ProtoPath。
	routes := s.Routes()
	doc, err := openapi.Build(s, routes, openapi.Info{Title: "echo", Version: "1.0.0"}, nil)
	if err != nil {
		t.Fatalf("openapi.Build: %v", err)
	}
	return doc
}

func TestBuildPathsAndSecurity(t *testing.T) {
	doc := exampleDoc(t)

	shout, ok := doc.Paths["/v1/echo:shout"]["post"]
	if !ok {
		t.Fatalf("POST /v1/echo:shout missing; paths=%v", doc.Paths)
	}
	if shout.OperationID == "" {
		t.Error("shout: operationId empty")
	}
	// Shout 声明 any_of(roles/scopes) 且非匿名 → bearer + x-grpcapi-requirements。
	if len(shout.Security) == 0 || len(shout.Security[0]["bearerAuth"]) != 0 {
		t.Errorf("shout: security = %v, want [{}]", shout.Security)
	}
	if !strings.Contains(jsonString(t, shout.XRequirements), "any_of") {
		t.Errorf("shout: x-grpcapi-requirements missing any_of: %v", shout.XRequirements)
	}
	if shout.RequestBody == nil || shout.RequestBody.Content["application/json"].Schema.Ref == "" {
		t.Errorf("shout: requestBody schema = %+v, want $ref", shout.RequestBody)
	}

	hear, ok := doc.Paths["/v1/echo"]["get"]
	if !ok {
		t.Fatalf("GET /v1/echo missing")
	}
	// Hear 无 body → filter 映射为查询参数；service default authenticated。
	if hear.RequestBody != nil {
		t.Errorf("hear: unexpected requestBody %+v", hear.RequestBody)
	}
	found := false
	for _, p := range hear.Parameters {
		if p.Name == "filter" && p.In == "query" && p.Schema.Type == "string" {
			found = true
		}
	}
	if !found {
		t.Errorf("hear: filter query param missing: %+v", hear.Parameters)
	}
	if len(hear.Security) == 0 || hear.Security[0]["bearerAuth"] == nil {
		t.Errorf("hear: security = %v, want bearerAuth", hear.Security)
	}

	ping, ok := doc.Paths["/v1/echo:ping"]["get"]
	if !ok {
		t.Fatalf("GET /v1/echo:ping missing")
	}
	// Ping 显式匿名 → security 必须是空数组（不继承全局）。
	if ping.Security == nil || len(ping.Security) != 0 {
		t.Errorf("ping: security = %v, want []", ping.Security)
	}
}

func TestBuildSchemas(t *testing.T) {
	doc := exampleDoc(t)
	want := map[string]map[string]string{
		"example.echo.v1.ShoutRequest":  {"text": "string"},
		"example.echo.v1.ShoutResponse": {"text": "string", "length": "integer"},
		"example.echo.v1.HearResponse":  {"lines": "array"},
	}
	for name, props := range want {
		s, ok := doc.Components.Schemas[name]
		if !ok {
			t.Fatalf("schema %s missing; have %v", name, keys(doc.Components.Schemas))
		}
		for field, typ := range props {
			f, ok := s.Properties[field]
			if !ok {
				t.Errorf("%s.%s missing", name, field)
				continue
			}
			if f.Type != typ {
				t.Errorf("%s.%s type = %q, want %q", name, field, f.Type, typ)
			}
		}
	}
	lines := doc.Components.Schemas["example.echo.v1.HearResponse"].Properties["lines"]
	if lines.Items == nil || lines.Items.Type != "string" {
		t.Errorf("HearResponse.lines items = %+v, want string", lines.Items)
	}
	if doc.Components.SecuritySchemes["bearerAuth"].Scheme != "bearer" {
		t.Errorf("bearerAuth scheme = %+v", doc.Components.SecuritySchemes["bearerAuth"])
	}
}

func TestGroupPrefixFinalPaths(t *testing.T) {
	set, err := policy.Build(context.Background(), policy.FromFiles(echov1.File_echo_proto), policy.Options{
		Provider: protopolicy.New(protopolicy.Options{}),
		Registry: policy.DefaultRegistry(),
	})
	if err != nil {
		t.Fatalf("policy.Build: %v", err)
	}
	s, err := surface.Build([]protoreflect.FileDescriptor{echov1.File_echo_proto}, set)
	if err != nil {
		t.Fatalf("surface.Build: %v", err)
	}
	// 模拟 server 加 API 组前缀后的最终路由表。
	routes := s.Routes()
	for i := range routes {
		routes[i].Path = "/api/v1" + strings.TrimPrefix(routes[i].ProtoPath, "/v1")
	}
	doc, err := openapi.Build(s, routes, openapi.Info{Title: "echo"}, nil)
	if err != nil {
		t.Fatalf("openapi.Build: %v", err)
	}
	if _, ok := doc.Paths["/api/v1/echo:ping"]["get"]; !ok {
		t.Errorf("prefixed path missing; paths=%v", doc.Paths)
	}
}

func TestBuildValidation(t *testing.T) {
	if _, err := openapi.Build(nil, nil, openapi.Info{Title: "x"}, nil); err == nil {
		t.Error("nil surface should fail")
	}
	doc := exampleDoc(t)
	if _, err := doc.JSON(); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if _, err := openapi.Handler(doc); err != nil {
		t.Fatalf("Handler: %v", err)
	}
	if _, err := openapi.Handler(nil); err == nil {
		t.Error("nil doc Handler should fail")
	}
}

func jsonString(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func keys(m map[string]*openapi.Schema) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
