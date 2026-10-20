package guard

import (
	"reflect"
	"strings"
	"testing"

	"github.com/lynx-go/grpcapi/surface"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// SDKOptions 是 SDK 覆盖检查的命名约定。
type SDKOptions struct {
	// FieldName 默认：服务名去 "Service" 后缀 + 首字母小写。
	FieldName func(protoreflect.ServiceDescriptor) string
	// MethodName 默认：RPC 原名。
	MethodName func(protoreflect.MethodDescriptor) string
}

// AssertSurfaceMethodCount 断言 Surface 中指定 API/前缀下方法总数。
func AssertSurfaceMethodCount(t testing.TB, surf *surface.Surface, api, prefix string, want int) {
	t.Helper()
	services := servicesFor(t, surf, api, prefix)
	count := 0
	for _, svc := range services {
		count += svc.Methods().Len()
	}
	if count != want {
		t.Fatalf("AssertSurfaceMethodCount: %s/%s 方法总数 = %d，与快照 %d 不符", api, prefix, count, want)
	}
}

// AssertSurfaceCoverage 断言 Surface 中每个 service/RPC 在 client 上都有
// 对应 wrapper 字段/方法。client 必须是结构体或指针。
func AssertSurfaceCoverage(t testing.TB, surf *surface.Surface, api, prefix string, client any, o SDKOptions) {
	t.Helper()
	if client == nil {
		t.Fatal("AssertSurfaceCoverage: client 为 nil：拒绝空转")
	}
	services := servicesFor(t, surf, api, prefix)
	cv := reflect.ValueOf(client)
	for cv.Kind() == reflect.Pointer {
		cv = cv.Elem()
	}
	if cv.Kind() != reflect.Struct {
		t.Fatalf("AssertSurfaceCoverage: client 必须是结构体（或其指针），得到 %s", cv.Kind())
	}
	ct := cv.Type()
	fieldName := o.FieldName
	if fieldName == nil {
		fieldName = func(sd protoreflect.ServiceDescriptor) string {
			return lowerFirst(strings.TrimSuffix(string(sd.Name()), "Service"))
		}
	}
	methodName := o.MethodName
	if methodName == nil {
		methodName = func(md protoreflect.MethodDescriptor) string { return string(md.Name()) }
	}
	for _, svc := range services {
		fn := fieldName(svc)
		field, ok := ct.FieldByName(fn)
		if !ok {
			t.Fatalf("client 缺少 %s 的 wrapper 字段 %q", svc.FullName(), fn)
		}
		ms := methodSetType(field.Type)
		methods := svc.Methods()
		for i := 0; i < methods.Len(); i++ {
			md := methods.Get(i)
			name := methodName(md)
			m, ok := ms.MethodByName(name)
			if !ok {
				t.Fatalf("%s.%s 缺少同名词导出方法（新增 RPC 未补 wrapper？）", svc.FullName(), name)
			}
			if m.PkgPath != "" {
				t.Fatalf("%s.%s 必须是导出方法", svc.FullName(), name)
			}
		}
	}
}

func servicesFor(t testing.TB, surf *surface.Surface, api, prefix string) []protoreflect.ServiceDescriptor {
	t.Helper()
	if surf == nil {
		t.Fatal("guard: Surface 为 nil：拒绝空转")
	}
	allowed := make(map[string]struct{})
	for _, op := range surf.Operations() {
		if api != "" && op.Operation.API != api {
			continue
		}
		allowed[op.Operation.Service] = struct{}{}
	}
	var out []protoreflect.ServiceDescriptor
	for _, svc := range surf.Services() {
		if _, ok := allowed[string(svc.FullName())]; !ok {
			continue
		}
		if prefix != "" && !nameUnderPrefix(string(svc.FullName()), prefix) {
			continue
		}
		out = append(out, svc)
	}
	if len(out) == 0 {
		t.Fatalf("guard: %s/%s 下未发现任何 service（API/前缀写错？拒绝空转）", api, prefix)
	}
	return out
}
