package guard

import (
	"context"
	"encoding/json"
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
