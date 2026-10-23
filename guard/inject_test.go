package guard

import (
	"context"
	"encoding/json"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	echov1 "github.com/lynx-go/grpcapi/example/echo/v1"
	"github.com/lynx-go/grpcapi/policy"
	"github.com/lynx-go/grpcapi/policy/protopolicy"
	"github.com/lynx-go/grpcapi/surface"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func injectSurface(t *testing.T) *surface.Surface {
	t.Helper()
	set, err := policy.Build(context.Background(), policy.FromFiles(echov1.File_echo_proto), policy.Options{
		Provider: protopolicy.New(protopolicy.Options{}),
		Registry: policy.DefaultRegistry(),
	})
	if err != nil {
		t.Fatal(err)
	}
	s, err := surface.Build([]protoreflect.FileDescriptor{echov1.File_echo_proto}, set)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// 无标签文档：注入后每个 operation 带上 Surface 派生 label。
func TestInjectLabelsAddsLabels(t *testing.T) {
	src := fstest.MapFS{"echo.swagger.json": &fstest.MapFile{Data: []byte(v2Doc)}}
	out, err := InjectLabels(src, InjectOptions{Surface: injectSurface(t)})
	if err != nil {
		t.Fatalf("InjectLabels: %v", err)
	}
	raw, err := fs.ReadFile(out, "echo.swagger.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	paths := doc["paths"].(map[string]any)
	for pathItem, methods := range paths {
		op := methods.(map[string]any)["get"]
		if op == nil {
			op = methods.(map[string]any)["post"]
		}
		got := op.(map[string]any)["x-grpcapi-policy"]
		if got == nil {
			t.Fatalf("%s: label missing after injection: %s", pathItem, raw)
		}
		if _, isStr := got.(string); !isStr {
			t.Fatalf("%s: label = %T, want string", pathItem, got)
		}
	}
	// 注入结果能被 loader 解析（闭环可用）。
	loader, err := OpenAPIv2(out, OpenAPIv2Options{})
	if err != nil {
		t.Fatal(err)
	}
	docs, err := loader.Load(context.Background())
	if err != nil {
		t.Fatalf("Load after inject: %v", err)
	}
	if len(docs) != 1 || len(docs[0].Operations) != 3 {
		t.Fatalf("docs = %d ops = %d", len(docs), len(docs[0].Operations))
	}
}

// 已有正确标签：幂等通过；已有错误标签：默认报错，Overwrite 覆盖。
func TestInjectLabelsConflictHandling(t *testing.T) {
	surf := injectSurface(t)
	bad := strings.Replace(v2Doc, `"x-grpcapi-policy": "public"`, `"x-grpcapi-policy": "wrong-label"`, 1)
	src := fstest.MapFS{"echo.swagger.json": &fstest.MapFile{Data: []byte(bad)}}
	if _, err := InjectLabels(src, InjectOptions{Surface: surf}); err == nil || !strings.Contains(err.Error(), "wrong-label") {
		t.Fatalf("err = %v, want conflict error exposing existing label", err)
	}
	out, err := InjectLabels(src, InjectOptions{Surface: surf, Overwrite: true})
	if err != nil {
		t.Fatalf("Overwrite: %v", err)
	}
	raw, _ := fs.ReadFile(out, "echo.swagger.json")
	if !strings.Contains(string(raw), `"x-grpcapi-policy": "public"`) {
		t.Fatalf("label not overwritten:\n%s", raw)
	}
	// 正确标签（不覆写）原样通过。
	out, err = InjectLabels(fstest.MapFS{"echo.swagger.json": &fstest.MapFile{Data: []byte(v2Doc)}}, InjectOptions{Surface: surf})
	if err != nil {
		t.Fatalf("idempotent inject: %v", err)
	}
	raw, _ = fs.ReadFile(out, "echo.swagger.json")
	if !strings.Contains(string(raw), `"x-grpcapi-policy": "public"`) {
		t.Fatalf("existing correct label lost:\n%s", raw)
	}
}

// 文档条目在 Surface 中不存在：默认报错，SkipUnknown 跳过。
func TestInjectLabelsUnknownOperation(t *testing.T) {
	withExtra := strings.Replace(v2Doc, `"/v1/echo:ping": {`, `"/v1/handwritten": {"get": {"operationId": "Manual_Thing", "responses": {"default": {"schema": {"$ref": "#/definitions/v1ErrorResponse"}}}}},
    "/v1/echo:ping": {`, 1)
	src := fstest.MapFS{"echo.swagger.json": &fstest.MapFile{Data: []byte(withExtra)}}
	if _, err := InjectLabels(src, InjectOptions{Surface: injectSurface(t)}); err == nil || !strings.Contains(err.Error(), "handwritten") {
		t.Fatalf("err = %v, want unknown-operation error", err)
	}
	if _, err := InjectLabels(src, InjectOptions{Surface: injectSurface(t), SkipUnknown: true}); err != nil {
		t.Fatalf("SkipUnknown: %v", err)
	}
}

// 非 OpenAPI 文件原样透传，注入 fs 可整体替换源 fs。
func TestInjectLabelsPassesThroughOtherFiles(t *testing.T) {
	src := fstest.MapFS{
		"echo.swagger.json": &fstest.MapFile{Data: []byte(v2Doc)},
		"notes.txt":         &fstest.MapFile{Data: []byte("keep me")},
	}
	out, err := InjectLabels(src, InjectOptions{Surface: injectSurface(t)})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := fs.ReadFile(out, "notes.txt")
	if err != nil || string(raw) != "keep me" {
		t.Fatalf("notes.txt = %q, %v; want verbatim passthrough", raw, err)
	}
}

func TestInjectLabelsRejectsInvalidInput(t *testing.T) {
	if _, err := InjectLabels(nil, InjectOptions{Surface: injectSurface(t)}); err == nil {
		t.Fatal("nil src should error")
	}
	if _, err := InjectLabels(fstest.MapFS{}, InjectOptions{}); err == nil {
		t.Fatal("nil Surface should error")
	}
}
