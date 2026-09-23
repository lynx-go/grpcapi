package guard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lynx-go/grpcapi/authz"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	swaggerFixturePkg  = "guardtest.swagger.v1"
	swaggerFixturePath = "guardtest/swagger/v1/demo.proto"
	swaggerFixtureSub  = "guardtest/swagger/v1"
)

// positiveSwaggerJSON 是与 fixture descriptor 匹配的正例 swagger：
// Ping（继承顶层 public）、Ping2（additional_bindings 数字后缀）、
// AdminPing（operation 级显式扩展）；default 响应引用动态可查的 v1ErrorResponse。
const positiveSwaggerJSON = `{
  "swagger": "2.0",
  "x-torchwood-access": "public",
  "paths": {
    "/v1/ping": {
      "get": {
        "operationId": "DemoService_Ping",
        "responses": {"default": {"schema": {"$ref": "#/definitions/v1ErrorResponse"}}}
      }
    },
    "/v1/ping:extra2": {
      "post": {
        "operationId": "DemoService_Ping2",
        "responses": {"default": {"schema": {"$ref": "#/definitions/v1ErrorResponse"}}}
      }
    },
    "/v1/admin-ping": {
      "post": {
        "operationId": "DemoService_AdminPing",
        "x-torchwood-access": "public",
        "responses": {"default": {"schema": {"$ref": "#/definitions/v1ErrorResponse"}}}
      }
    }
  },
  "definitions": {
    "v1ErrorResponse": {"type": "object", "properties": {"error_id": {"type": "string"}}}
  }
}`

// setupSwaggerFixture 落盘最小手写 swagger fixture（临时目录），返回
// (root, 文件描述符, 策略注册表)。root 下另放一个无对应 proto 的 swagger
// 文件驱动跳过路径。
func setupSwaggerFixture(t *testing.T, swaggerJSON string) (string, protoreflect.FileDescriptor, *authz.PolicySet) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, swaggerFixtureSub)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "demo.swagger.json"), []byte(swaggerJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "unrelated.swagger.json"),
		[]byte(`{"swagger":"2.0","paths":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	fd := fixtureFileDescriptor(t, swaggerFixturePath, swaggerFixturePkg, 1)
	return root, fd, fixturePolicies(t, fd)
}

// swaggerBaseOptions 返回与 fixture 匹配的最小合法选项。
func swaggerBaseOptions(root string, fd protoreflect.FileDescriptor, set *authz.PolicySet) SwaggerOptions {
	return SwaggerOptions{
		GenprotoSubdirs: []string{swaggerFixtureSub},
		GenprotoRoot:    root,
		Files:           []protoreflect.FileDescriptor{fd},
		Policies:        set,
		AccessExtension: "x-torchwood-access",
		MinFiles:        1,
		MinOps:          3,
		ServiceAccess: func(string) (string, bool) {
			return "public", true
		},
	}
}

func TestSwaggerAccessMatchesPositive(t *testing.T) {
	root, fd, set := setupSwaggerFixture(t, positiveSwaggerJSON)
	SwaggerAccessMatches(t, swaggerBaseOptions(root, fd, set))
}

// TestSwaggerAccessMatchesExplicitErrorRef 覆盖 ErrorResponseRef 显式指定路径
// （正例的动态查找路径已在 Positive 覆盖）。
func TestSwaggerAccessMatchesExplicitErrorRef(t *testing.T) {
	root, fd, set := setupSwaggerFixture(t, positiveSwaggerJSON)
	opts := swaggerBaseOptions(root, fd, set)
	opts.ErrorResponseRef = "#/definitions/v1ErrorResponse"
	SwaggerAccessMatches(t, opts)
}

func TestSwaggerAccessMatchesRejectsEmptyOptions(t *testing.T) {
	root, fd, set := setupSwaggerFixture(t, positiveSwaggerJSON)
	base := swaggerBaseOptions(root, fd, set)

	expectGuardFatal(t, "Files 空", func(_ *testing.T, tb testing.TB) {
		o := base
		o.Files = nil
		swaggerAccessMatches(tb, o)
	})
	expectGuardFatal(t, "Policies nil", func(_ *testing.T, tb testing.TB) {
		o := base
		o.Policies = nil
		swaggerAccessMatches(tb, o)
	})
	expectGuardFatal(t, "ServiceAccess nil", func(_ *testing.T, tb testing.TB) {
		o := base
		o.ServiceAccess = nil
		swaggerAccessMatches(tb, o)
	})
	expectGuardFatal(t, "GenprotoRoot 空", func(_ *testing.T, tb testing.TB) {
		o := base
		o.GenprotoRoot = ""
		swaggerAccessMatches(tb, o)
	})
	expectGuardFatal(t, "Subdirs 空", func(_ *testing.T, tb testing.TB) {
		o := base
		o.GenprotoSubdirs = nil
		swaggerAccessMatches(tb, o)
	})
	expectGuardFatal(t, "MinOps 零值", func(_ *testing.T, tb testing.TB) {
		o := base
		o.MinOps = 0
		swaggerAccessMatches(tb, o)
	})
	expectGuardFatal(t, "MinOps 超规模", func(_ *testing.T, tb testing.TB) {
		o := base
		o.MinOps = 1000
		swaggerAccessMatches(tb, o)
	})
	expectGuardFatal(t, "MinFiles 超规模", func(_ *testing.T, tb testing.TB) {
		o := base
		o.MinFiles = 100
		swaggerAccessMatches(tb, o)
	})
}

func TestSwaggerAccessMatchesDetectsDrift(t *testing.T) {
	expectGuardFatal(t, "operation 级扩展与策略不一致", func(st *testing.T, tb testing.TB) {
		drifted := strings.Replace(positiveSwaggerJSON,
			`"operationId": "DemoService_AdminPing",
        "x-torchwood-access": "public"`,
			`"operationId": "DemoService_AdminPing",
        "x-torchwood-access": "server"`, 1)
		if drifted == positiveSwaggerJSON {
			st.Fatal("fixture 替换未生效")
		}
		r, f, s := setupSwaggerFixture(st, drifted)
		swaggerAccessMatches(tb, swaggerBaseOptions(r, f, s))
	})

	expectGuardFatal(t, "顶层扩展与服务默认档不一致", func(st *testing.T, tb testing.TB) {
		drifted := strings.Replace(positiveSwaggerJSON,
			`"x-torchwood-access": "public"`,
			`"x-torchwood-access": "end_user"`, 1)
		r, f, s := setupSwaggerFixture(st, drifted)
		swaggerAccessMatches(tb, swaggerBaseOptions(r, f, s))
	})

	expectGuardFatal(t, "default 响应引用失真", func(st *testing.T, tb testing.TB) {
		// 全部 operation 的 default ref 换成生成器默认的 rpcStatus：动态查找仍
		// 命中 v1ErrorResponse 定义，ref 比对失真即红。
		drifted := strings.Replace(positiveSwaggerJSON,
			`"#/definitions/v1ErrorResponse"`, `"#/definitions/rpcStatus"`, -1)
		if drifted == positiveSwaggerJSON {
			st.Fatal("fixture 替换未生效")
		}
		r, f, s := setupSwaggerFixture(st, drifted)
		swaggerAccessMatches(tb, swaggerBaseOptions(r, f, s))
	})

	expectGuardFatal(t, "反向覆盖缺口（漏 http 注解形态）", func(st *testing.T, tb testing.TB) {
		// 连同前一项的尾逗号整块删除 admin-ping 路径：策略表仍有 AdminPing，
		// swagger 缺失即红。
		drifted := strings.Replace(positiveSwaggerJSON, `    },
    "/v1/admin-ping": {
      "post": {
        "operationId": "DemoService_AdminPing",
        "x-torchwood-access": "public",
        "responses": {"default": {"schema": {"$ref": "#/definitions/v1ErrorResponse"}}}
      }
    }
  },`, `    }
  },`, 1)
		if drifted == positiveSwaggerJSON {
			st.Fatal("fixture 替换未生效")
		}
		r, f, s := setupSwaggerFixture(st, drifted)
		swaggerAccessMatches(tb, swaggerBaseOptions(r, f, s))
	})

	expectGuardFatal(t, "operationId 数字后缀越界", func(st *testing.T, tb testing.TB) {
		// Ping 无 additional_bindings，但 swagger 仍带 Ping2 → 后缀越界即红。
		r := st.TempDir()
		dir := filepath.Join(r, swaggerFixtureSub)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			st.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "demo.swagger.json"), []byte(positiveSwaggerJSON), 0o644); err != nil {
			st.Fatal(err)
		}
		f := fixtureFileDescriptor(st, swaggerFixturePath, swaggerFixturePkg, 0)
		s := fixturePolicies(st, f)
		swaggerAccessMatches(tb, swaggerBaseOptions(r, f, s))
	})
}

func TestSwaggerAccessMatchesDynamicRefAmbiguous(t *testing.T) {
	// 两个候选定义 → 动态查找歧义 Fatal；显式 ref 可解锁。
	ambiguous := strings.Replace(positiveSwaggerJSON,
		`"definitions": {`,
		`"definitions": {
    "v2ErrorResponse": {"type": "object"},`,
		1)
	root, fd, set := setupSwaggerFixture(t, ambiguous)
	expectGuardFatal(t, "歧义定义", func(_ *testing.T, tb testing.TB) {
		swaggerAccessMatches(tb, swaggerBaseOptions(root, fd, set))
	})
	opts := swaggerBaseOptions(root, fd, set)
	opts.ErrorResponseRef = "#/definitions/v1ErrorResponse"
	SwaggerAccessMatches(t, opts)
}

func TestSwaggerSnakeCaseProperties(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, swaggerFixtureSub)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	bad := `{"definitions": {"v1Thing": {"properties": {"ok_field": {"type": "string"}, "badField": {"type": "string"}, "@type": {"type": "string"}}}}}`
	if err := os.WriteFile(filepath.Join(dir, "demo.swagger.json"), []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}

	expectGuardFatal(t, "camelCase 属性", func(_ *testing.T, tb testing.TB) {
		swaggerSnakeCaseProperties(tb, root, []string{swaggerFixtureSub})
	})

	good := `{"definitions": {"v1Thing": {"properties": {"ok_field": {"type": "string"}, "@type": {"type": "string"}}}}}`
	if err := os.WriteFile(filepath.Join(dir, "demo.swagger.json"), []byte(good), 0o644); err != nil {
		t.Fatal(err)
	}
	SwaggerSnakeCaseProperties(t, root, []string{swaggerFixtureSub})

	expectGuardFatal(t, "空参", func(_ *testing.T, tb testing.TB) {
		swaggerSnakeCaseProperties(tb, "", nil)
	})
	expectGuardFatal(t, "目录不存在", func(_ *testing.T, tb testing.TB) {
		swaggerSnakeCaseProperties(tb, t.TempDir(), []string{"nothing/here"})
	})
}

func TestSwaggerNoDefinition(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, swaggerFixtureSub)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	dirty := `{"definitions": {"rpcStatus": {}},"paths":{"/v1/ping":{"get":{"responses":{"default":{"$ref":"#/definitions/rpcStatus"}}}}}}`
	if err := os.WriteFile(filepath.Join(dir, "demo.swagger.json"), []byte(dirty), 0o644); err != nil {
		t.Fatal(err)
	}

	expectGuardFatal(t, "含 rpcStatus（定义+引用都算）", func(_ *testing.T, tb testing.TB) {
		swaggerNoDefinition(tb, root, []string{swaggerFixtureSub}, "rpcStatus")
	})

	clean := `{"definitions": {"v1ErrorResponse": {}},"paths":{}}`
	if err := os.WriteFile(filepath.Join(dir, "demo.swagger.json"), []byte(clean), 0o644); err != nil {
		t.Fatal(err)
	}
	SwaggerNoDefinition(t, root, []string{swaggerFixtureSub}, "rpcStatus")

	expectGuardFatal(t, "banned 空", func(_ *testing.T, tb testing.TB) {
		swaggerNoDefinition(tb, root, []string{swaggerFixtureSub}, "")
	})
	expectGuardFatal(t, "目录不存在", func(_ *testing.T, tb testing.TB) {
		swaggerNoDefinition(tb, t.TempDir(), []string{"nothing/here"}, "rpcStatus")
	})
}
