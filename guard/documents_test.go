package guard

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	echov1 "github.com/lynx-go/grpcapi/example/echo/v1"
	"github.com/lynx-go/grpcapi/policy"
	"github.com/lynx-go/grpcapi/policy/protopolicy"
	"github.com/lynx-go/grpcapi/surface"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func testSurface(t *testing.T) *surface.Surface {
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

const v2Doc = `{
  "swagger": "2.0",
  "x-grpcapi-policy": "authenticated",
  "paths": {
    "/v1/echo:shout": {
      "post": {
        "operationId": "EchoService_Shout",
        "x-grpcapi-policy": "server",
        "responses": {"default": {"schema": {"$ref": "#/definitions/v1ErrorResponse"}}}
      }
    },
    "/v1/echo": {
      "get": {
        "operationId": "EchoService_Hear",
        "responses": {"default": {"schema": {"$ref": "#/definitions/v1ErrorResponse"}}}
      }
    },
    "/v1/echo:ping": {
      "get": {
        "operationId": "EchoService_Ping",
        "x-grpcapi-policy": "public",
        "responses": {"default": {"schema": {"$ref": "#/definitions/v1ErrorResponse"}}}
      }
    }
  },
  "definitions": {
    "v1ErrorResponse": {"type": "object", "properties": {"error_id": {"type": "string"}}}
  }
}`

const v3Doc = `{
  "openapi": "3.0.0",
  "x-grpcapi-policy": "authenticated",
  "paths": {
    "/v1/echo:shout": {
      "post": {
        "operationId": "EchoService_Shout",
        "x-grpcapi-policy": "server",
        "responses": {"default": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/v1ErrorResponse"}}}}}
      }
    },
    "/v1/echo": {
      "get": {
        "operationId": "EchoService_Hear",
        "responses": {"default": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/v1ErrorResponse"}}}}}
      }
    },
    "/v1/echo:ping": {
      "get": {
        "operationId": "EchoService_Ping",
        "x-grpcapi-policy": "public",
        "responses": {"default": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/v1ErrorResponse"}}}}}
      }
    }
  },
  "components": {"schemas": {"v1ErrorResponse": {"type": "object", "properties": {"error_id": {"type": "string"}}}}}
}`

func docOptions(ref string) MatchOptions {
	return MatchOptions{
		MetadataKey:   "x-grpcapi-policy",
		CheckTopLevel: true,
		ServiceLabel:  func(string) (string, bool) { return "authenticated", true },
		ErrorRef:      func(Document, DocumentOperation) (string, bool) { return ref, true },
		MinDocuments:  1,
		MinOperations: 3,
	}
}

func TestAssertDocumentsV2(t *testing.T) {
	fsys := fstest.MapFS{"api.swagger.json": &fstest.MapFile{Data: []byte(v2Doc)}}
	loader, err := OpenAPIv2(fsys, OpenAPIv2Options{})
	if err != nil {
		t.Fatal(err)
	}
	AssertDocuments(t, loader, testSurface(t), docOptions("#/definitions/v1ErrorResponse"))
}

func TestAssertDocumentsV3(t *testing.T) {
	fsys := fstest.MapFS{"api.openapi.json": &fstest.MapFile{Data: []byte(v3Doc)}}
	loader, err := OpenAPIv3(fsys, OpenAPIv3Options{})
	if err != nil {
		t.Fatal(err)
	}
	AssertDocuments(t, loader, testSurface(t), docOptions("#/components/schemas/v1ErrorResponse"))
}

func TestAssertDocumentsRejectsOperationIDPathMismatch(t *testing.T) {
	bad := replaceOnce(v2Doc, `"/v1/echo:shout"`, `"/v1/echo:wrong"`)
	fsys := fstest.MapFS{"api.swagger.json": &fstest.MapFile{Data: []byte(bad)}}
	loader, err := OpenAPIv2(fsys, OpenAPIv2Options{})
	if err != nil {
		t.Fatal(err)
	}
	expectGuardFatal(t, "not in surface", func(st *testing.T, tb testing.TB) {
		AssertDocuments(tb, loader, testSurface(st), docOptions("#/definitions/v1ErrorResponse"))
	})
}

func TestAssertDocumentsLabelDrift(t *testing.T) {
	drifted := replaceOnce(v2Doc, `"x-grpcapi-policy": "server"`, `"x-grpcapi-policy": "public"`)
	fsys := fstest.MapFS{"api.swagger.json": &fstest.MapFile{Data: []byte(drifted)}}
	loader, _ := OpenAPIv2(fsys, OpenAPIv2Options{})
	expectGuardFatal(t, "label drift", func(_ *testing.T, tb testing.TB) {
		AssertDocuments(tb, loader, testSurface(t), docOptions("#/definitions/v1ErrorResponse"))
	})
}

func TestAssertDocumentsMissingOperation(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal([]byte(v2Doc), &doc); err != nil {
		t.Fatal(err)
	}
	delete(doc["paths"].(map[string]any), "/v1/echo:ping")
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	fsys := fstest.MapFS{"api.swagger.json": &fstest.MapFile{Data: raw}}
	loader, _ := OpenAPIv2(fsys, OpenAPIv2Options{})
	expectGuardFatal(t, "missing operation", func(_ *testing.T, tb testing.TB) {
		AssertDocuments(tb, loader, testSurface(t), docOptions("#/definitions/v1ErrorResponse"))
	})
}

func TestAssertJSONNamingAndNoSchema(t *testing.T) {
	snakeBad := []Document{{
		Path: "api.json",
		Raw:  []byte(`{"definitions":{"v1Thing":{"properties":{"ok_field":{"type":"string"},"badField":{"type":"string"},"@type":{"type":"string"}}}}}`),
		Definitions: map[string]json.RawMessage{
			"v1Thing": json.RawMessage(`{"properties":{"ok_field":{"type":"string"},"badField":{"type":"string"},"@type":{"type":"string"}}}`),
		},
	}}
	expectGuardFatal(t, "snake case violation", func(_ *testing.T, tb testing.TB) {
		AssertJSONNaming(tb, snakeBad, SnakeCase)
	})

	snakeGood := []Document{{
		Path: "api.json",
		Raw:  []byte(`{"definitions":{"v1Thing":{"properties":{"ok_field":{"type":"string"},"@type":{"type":"string"}}}}}`),
		Definitions: map[string]json.RawMessage{
			"v1Thing": json.RawMessage(`{"properties":{"ok_field":{"type":"string"},"@type":{"type":"string"}}}`),
		},
	}}
	AssertJSONNaming(t, snakeGood, SnakeCase)

	camelGood := []Document{{
		Path: "api.json",
		Raw:  []byte(`{"definitions":{"v1Thing":{"properties":{"okField":{"type":"string"},"@type":{"type":"string"}}}}}`),
		Definitions: map[string]json.RawMessage{
			"v1Thing": json.RawMessage(`{"properties":{"okField":{"type":"string"},"@type":{"type":"string"}}}`),
		},
	}}
	AssertJSONNaming(t, camelGood, CamelCase)

	banned := []Document{{
		Path: "api.json",
		Raw:  []byte(`{"definitions":{"rpcStatus":{}}}`),
	}}
	expectGuardFatal(t, "banned schema", func(_ *testing.T, tb testing.TB) {
		AssertNoSchema(tb, banned, "rpcStatus")
	})
	AssertNoSchema(t, []Document{{Path: "clean.json", Raw: []byte(`{"definitions":{}}`)}}, "rpcStatus")
}

func TestSuitePolicyAndNaming(t *testing.T) {
	fsys := fstest.MapFS{"api.swagger.json": &fstest.MapFile{Data: []byte(v2Doc)}}
	loader, _ := OpenAPIv2(fsys, OpenAPIv2Options{})
	Run(t, SuiteConfig{
		Surface: testSurface(t),
		Docs:    loader,
		Policy:  docOptions("#/definitions/v1ErrorResponse"),
		Naming:  SnakeCase,
	})
}

func replaceOnce(s, old, new string) string {
	if i := indexOf(s, old); i >= 0 {
		return s[:i] + new + s[i+len(old):]
	}
	return s
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestStripPrefix(t *testing.T) {
	norm := surface.NormalizePath
	cases := []struct {
		name   string
		path   string
		prefix string
		want   string
	}{
		{"无前缀配置原样", "/v1/echo", "", "/v1/echo"},
		{"剥前缀", "/pre/v1/echo", "/pre", "/v1/echo"},
		{"全剥成根", "/pre", "/pre", "/"},
		{"非 path 段边界不剥", "/prefix/v1/echo", "/pre", "/prefix/v1/echo"},
		{"path 先归一再比对", "pre/v1/echo", "/pre", "/v1/echo"},
		{"无关前缀原样", "/other/v1/echo", "/pre", "/other/v1/echo"},
	}
	for _, tc := range cases {
		if got := stripPrefix(tc.path, tc.prefix, norm); got != tc.want {
			t.Errorf("%s: stripPrefix(%q, %q) = %q, want %q", tc.name, tc.path, tc.prefix, got, tc.want)
		}
	}
}

func TestMatchByOperationID(t *testing.T) {
	byOpID := map[string][]string{
		"EchoService_Ping":  {"get /v1/echo:ping"},
		"EchoService_Both":  {"get /a", "post /b"},
		"EchoService_Empty": {},
	}
	cases := []struct {
		name     string
		id       string
		disabled bool
		want     string
		wantOK   bool
	}{
		{"唯一命中", "EchoService_Ping", false, "get /v1/echo:ping", true},
		{"多绑定不放行", "EchoService_Both", false, "", false},
		{"空表不放行", "EchoService_Empty", false, "", false},
		{"空 id 不放行", "", false, "", false},
		{"显式禁用不放行", "EchoService_Ping", true, "", false},
		{"数字后缀回退基名", "EchoService_Ping2", false, "get /v1/echo:ping", true},
		{"多位数字后缀", "EchoService_Ping22", false, "get /v1/echo:ping", true},
		{"基名多绑定不放行", "EchoService_Both3", false, "", false},
		{"未知基名不放行", "EchoService_Nope9", false, "", false},
	}
	for _, tc := range cases {
		got, ok := matchByOperationID(tc.id, byOpID, tc.disabled)
		if ok != tc.wantOK || (ok && got != tc.want) {
			t.Errorf("%s: matchByOperationID(%q) = (%q, %v), want (%q, %v)",
				tc.name, tc.id, got, ok, tc.want, tc.wantOK)
		}
	}
}

// prefixedDoc 把 v2Doc 的全部 path 挂到部署前缀下（模拟网关部署形态）。
func prefixedDoc(t *testing.T, prefix string) string {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(v2Doc), &doc); err != nil {
		t.Fatal(err)
	}
	paths := map[string]any{}
	for k, v := range doc["paths"].(map[string]any) {
		paths[prefix+k] = v
	}
	doc["paths"] = paths
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestAssertDocumentsStripsDeploymentPrefix(t *testing.T) {
	fsys := fstest.MapFS{"api.swagger.json": &fstest.MapFile{Data: []byte(prefixedDoc(t, "/pre"))}}
	loader, _ := OpenAPIv2(fsys, OpenAPIv2Options{})
	opts := docOptions("#/definitions/v1ErrorResponse")
	opts.Prefix = "/pre"
	AssertDocuments(t, loader, testSurface(t), opts)

	// 未配置前缀时带前缀文档不得匹配（前缀剥离不是宽容匹配）。
	noPrefix := fstest.MapFS{"api.swagger.json": &fstest.MapFile{Data: []byte(prefixedDoc(t, "/pre"))}}
	loader2, _ := OpenAPIv2(noPrefix, OpenAPIv2Options{})
	expectGuardFatal(t, "prefix not stripped", func(_ *testing.T, tb testing.TB) {
		AssertDocuments(tb, loader2, testSurface(t), docOptions("#/definitions/v1ErrorResponse"))
	})
}

// runSDK 是 Run 的 SDK 覆盖检查用 client 桩（EchoService → echo 字段）。
type runSDK struct{ echo runEchoSDK }

type runEchoSDK struct{}

func (runEchoSDK) Shout(*echov1.ShoutRequest) {}
func (runEchoSDK) Hear(*echov1.HearRequest)   {}
func (runEchoSDK) Ping(*echov1.PingRequest)   {}

func TestRunAllChecks(t *testing.T) {
	surf := testSurface(t)
	fsys := fstest.MapFS{"api.swagger.json": &fstest.MapFile{Data: []byte(v2Doc)}}
	loader, _ := OpenAPIv2(fsys, OpenAPIv2Options{})

	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "policy.manifest.json")
	manifestData, err := surf.Policy().Manifest().JSON()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, manifestData, 0o600); err != nil {
		t.Fatal(err)
	}
	matrixPath := filepath.Join(dir, "authz-matrix.md")
	matrixOpts := MatrixOptions{
		Header: []string{"Method", "Label"},
		Row: func(op policy.Operation) []string {
			return []string{op.ID, op.EffectiveLabel()}
		},
	}
	matrixData, err := RenderMatrix(surf.Policy(), matrixOpts)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(matrixPath, matrixData, 0o600); err != nil {
		t.Fatal(err)
	}

	Run(t, SuiteConfig{
		Surface:  surf,
		Docs:     loader,
		Policy:   docOptions("#/definitions/v1ErrorResponse"),
		Naming:   SnakeCase,
		Banned:   []string{"rpcStatus"},
		SDK:      &SDKConfig{Client: runSDK{}},
		Manifest: &ManifestConfig{Path: manifestPath},
		Matrix:   &MatrixConfig{Path: matrixPath, Options: matrixOpts},
	})
}

type errLoader struct{}

func (errLoader) Load(context.Context) ([]Document, error) {
	return nil, errors.New("docs unavailable")
}

func TestRunFailureModes(t *testing.T) {
	expectGuardFatal(t, "nil surface", func(_ *testing.T, tb testing.TB) {
		Run(tb, SuiteConfig{})
	})
	expectGuardFatal(t, "docs load error", func(st *testing.T, tb testing.TB) {
		Run(tb, SuiteConfig{Surface: testSurface(st), Docs: errLoader{}})
	})
	expectGuardFatal(t, "naming requires docs", func(st *testing.T, tb testing.TB) {
		Run(tb, SuiteConfig{Surface: testSurface(st), Naming: SnakeCase})
	})
	// matrix 快照漂移：磁盘内容与渲染结果不一致必须 Fatal。
	expectGuardFatal(t, "matrix drift", func(st *testing.T, tb testing.TB) {
		path := filepath.Join(st.TempDir(), "authz-matrix.md")
		if err := os.WriteFile(path, []byte("stale content\n"), 0o600); err != nil {
			st.Fatal(err)
		}
		Run(tb, SuiteConfig{
			Surface: testSurface(st),
			Matrix: &MatrixConfig{Path: path, Options: MatrixOptions{
				Header: []string{"Method", "Label"},
				Row: func(op policy.Operation) []string {
					return []string{op.ID, op.EffectiveLabel()}
				},
			}},
		})
	})
}
